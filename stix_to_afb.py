#!/usr/bin/env python3
"""
STIX to Attack Flow Builder (AFB) Converter

Converts STIX 2.1 JSON bundles to Attack Flow Builder (.afb) format.
The AFB format is the native format used by MITRE's Attack Flow Builder tool.

Usage:
    python stix_to_afb.py input.stix.json output.afb
    python stix_to_afb.py input.stix.json  # outputs to input.afb
"""

import json
import uuid
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


def generate_uuid() -> str:
    """Generate a new UUID."""
    return str(uuid.uuid4())


def get_anchor_type(position: int) -> str:
    """
    Determine anchor type based on position (degrees).
    Horizontal anchors: 0, 30, 150, 180, 210, 330 (top/bottom areas)
    Vertical anchors: 60, 90, 120, 240, 270, 300 (left/right areas)
    """
    if position in (0, 30, 150, 180, 210, 330):
        return "horizontal_anchor"
    else:
        return "vertical_anchor"


def create_anchors_for_object() -> tuple[dict[str, str], list[dict]]:
    """
    Create 12 anchor objects for a block object (action, asset, etc).
    Returns (anchors_dict, list of anchor objects).
    """
    anchors = {}
    anchor_objects = []

    positions = [0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330]

    for pos in positions:
        anchor_id = generate_uuid()
        anchor_type = get_anchor_type(pos)

        anchors[str(pos)] = anchor_id
        anchor_objects.append({
            "id": anchor_type,
            "instance": anchor_id,
            "latches": []
        })

    return anchors, anchor_objects


def extract_technique_info(attack_pattern: dict) -> tuple[str | None, str | None, str | None, str | None]:
    """
    Extract MITRE ATT&CK tactic and technique IDs from external references.
    Returns (tactic_id, tactic_ref, technique_id, technique_ref).
    """
    external_refs = attack_pattern.get("external_references", [])
    technique_id = None
    technique_ref = None
    tactic_id = None
    tactic_ref = None

    for ref in external_refs:
        if ref.get("source_name") == "mitre-attack":
            technique_id = ref.get("external_id")

    # Extract tactic from kill_chain_phases
    kill_chain = attack_pattern.get("kill_chain_phases", [])
    for phase in kill_chain:
        if phase.get("kill_chain_name") == "mitre-attack":
            phase_name = phase.get("phase_name", "")
            # Map phase names to tactic IDs and refs
            tactic_map = {
                "reconnaissance": ("TA0043", "x-mitre-tactic--daa4cbb1-b4f4-4723-a824-7f1efd6e0592"),
                "resource-development": ("TA0042", "x-mitre-tactic--d679bca2-e57d-4935-8650-8031c87a4400"),
                "initial-access": ("TA0001", "x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca"),
                "execution": ("TA0002", "x-mitre-tactic--4ca45d45-df4d-4613-8571-d07766f4c8d0"),
                "persistence": ("TA0003", "x-mitre-tactic--5bc1d813-693e-4823-9961-abf9571d8211"),
                "privilege-escalation": ("TA0004", "x-mitre-tactic--5e29b093-294e-49e9-a803-dab3d73b77dd"),
                "defense-evasion": ("TA0005", "x-mitre-tactic--78b23412-0651-46d7-a540-170a1ce8bd5a"),
                "credential-access": ("TA0006", "x-mitre-tactic--2558fd61-8c75-4730-94c4-11926db2a263"),
                "discovery": ("TA0007", "x-mitre-tactic--c17c5845-175e-4421-9713-829d0573dbc9"),
                "lateral-movement": ("TA0008", "x-mitre-tactic--7141578b-e50b-4dcc-bfa4-08a8dd689e9e"),
                "collection": ("TA0009", "x-mitre-tactic--d108ce10-2419-4cf9-a774-46161d6c6cfe"),
                "command-and-control": ("TA0011", "x-mitre-tactic--f72804c5-f15a-449e-a5da-2eecd181f813"),
                "exfiltration": ("TA0010", "x-mitre-tactic--9a4e74ab-5008-408c-84bf-a10dfbc53462"),
                "impact": ("TA0040", "x-mitre-tactic--5569339b-94c2-49ee-afb3-2222936571bc")
            }
            if phase_name in tactic_map:
                tactic_id, tactic_ref = tactic_map[phase_name]
            break

    return tactic_id, tactic_ref, technique_id, technique_ref


def create_action_object(attack_pattern: dict) -> tuple[dict, list[dict]]:
    """
    Create an AFB action object from a STIX attack-pattern.
    Returns the action object and a list of anchor objects.
    """
    instance_id = generate_uuid()
    tactic_id, tactic_ref, technique_id, technique_ref = extract_technique_info(attack_pattern)

    anchors, anchor_objects = create_anchors_for_object()

    # Build properties array
    properties = [
        ["name", attack_pattern.get("name", "Unknown Action")],
        ["tactic_id", tactic_id],
        ["tactic_ref", tactic_ref],
        ["technique_id", technique_id],
        ["technique_ref", technique_ref],
        ["description", attack_pattern.get("description", "")],
        ["confidence", None],
        ["execution_start", None],
        ["execution_end", None]
    ]

    # Add TTP tuple if we have tactic/technique
    if tactic_id and technique_id:
        properties.append(["ttp", [["tactic", tactic_id], ["technique", technique_id]]])
    else:
        properties.append(["ttp", None])

    action = {
        "id": "action",
        "instance": instance_id,
        "properties": properties,
        "anchors": anchors
    }

    return action, anchor_objects


def create_asset_object(source_obj: dict) -> tuple[dict, list[dict]]:
    """
    Create an AFB asset object from a STIX infrastructure/malware/tool object.
    Returns the asset object and a list of anchor objects.
    """
    instance_id = generate_uuid()
    anchors, anchor_objects = create_anchors_for_object()

    properties = [
        ["name", source_obj.get("name", "Unknown Asset")],
        ["description", source_obj.get("description", "")]
    ]

    asset = {
        "id": "asset",
        "instance": instance_id,
        "properties": properties,
        "anchors": anchors
    }

    return asset, anchor_objects


def create_course_of_action_object(coa: dict) -> tuple[dict, list[dict]]:
    """
    Create an AFB course_of_action object from a STIX course-of-action.
    Returns the course_of_action object and a list of anchor objects.
    """
    instance_id = generate_uuid()
    anchors, anchor_objects = create_anchors_for_object()

    properties = [
        ["name", coa.get("name", "Unknown Mitigation")],
        ["description", coa.get("description", "")],
        ["action_type", coa.get("action_type", "")],
        ["os_execution_envs", []],
        ["action_bin", ""]
    ]

    course_of_action = {
        "id": "course_of_action",
        "instance": instance_id,
        "properties": properties,
        "anchors": anchors
    }

    return course_of_action, anchor_objects


def create_connection(
    source_anchor_objects: list[dict],
    target_anchor_objects: list[dict],
    source_position: str = "90",  # right side
    target_position: str = "270"  # left side
) -> tuple[list[dict], list[dict]]:
    """
    Create a connection between two objects.
    Returns (connection objects, updated anchor objects).
    """
    connection_objects = []

    # Find source and target anchors
    source_anchor = None
    target_anchor = None

    for anchor in source_anchor_objects:
        # Find the anchor that matches the position
        pass  # We'll update latches directly

    for anchor in target_anchor_objects:
        pass

    # Create generic_latch for source
    source_latch_id = generate_uuid()
    source_latch = {
        "id": "generic_latch",
        "instance": source_latch_id
    }
    connection_objects.append(source_latch)

    # Create generic_latch for target
    target_latch_id = generate_uuid()
    target_latch = {
        "id": "generic_latch",
        "instance": target_latch_id
    }
    connection_objects.append(target_latch)

    # Create generic_handle
    handle_id = generate_uuid()
    handle = {
        "id": "generic_handle",
        "instance": handle_id
    }
    connection_objects.append(handle)

    # Create dynamic_line
    line_id = generate_uuid()
    line = {
        "id": "dynamic_line",
        "instance": line_id,
        "source": source_latch_id,
        "target": target_latch_id,
        "handles": [handle_id]
    }
    connection_objects.append(line)

    # Update anchor latches
    for anchor in source_anchor_objects:
        # Find anchor by checking if it's in the right position
        # Since we created them in order, position 90 is index 3
        pass

    return connection_objects, source_latch_id, target_latch_id


def build_flow_graph(relationships: list[dict]) -> dict[str, list[str]]:
    """
    Build a directed graph from STIX relationships.
    Returns mapping of source_ref -> list of target_refs for 'precedes' relationships.
    """
    flow_graph: dict[str, list[str]] = {}

    for rel in relationships:
        rel_type = rel.get("relationship_type", "")
        source = rel.get("source_ref", "")
        target = rel.get("target_ref", "")

        if rel_type == "precedes":
            if source not in flow_graph:
                flow_graph[source] = []
            flow_graph[source].append(target)

    return flow_graph


def find_start_nodes(
    attack_patterns: list[dict],
    flow_graph: dict[str, list[str]]
) -> list[str]:
    """Find attack patterns that are not preceded by any other pattern."""
    all_pattern_ids = {ap["id"] for ap in attack_patterns}
    preceded_ids = set()

    for targets in flow_graph.values():
        for t in targets:
            if t in all_pattern_ids:
                preceded_ids.add(t)

    start_ids = all_pattern_ids - preceded_ids
    return list(start_ids)


def topological_sort(
    attack_patterns: list[dict],
    flow_graph: dict[str, list[str]]
) -> list[dict]:
    """Sort attack patterns in topological order for layout."""
    pattern_map = {ap["id"]: ap for ap in attack_patterns}
    visited = set()
    result = []

    def visit(node_id: str):
        if node_id in visited or node_id not in pattern_map:
            return
        visited.add(node_id)
        for target in flow_graph.get(node_id, []):
            visit(target)
        result.append(pattern_map[node_id])

    start_nodes = find_start_nodes(attack_patterns, flow_graph)
    for start in sorted(start_nodes):
        visit(start)

    # Add any unvisited nodes
    for ap in attack_patterns:
        if ap["id"] not in visited:
            result.append(ap)

    return list(reversed(result))


def convert_stix_to_afb(stix_bundle: dict) -> dict:
    """
    Convert a STIX 2.1 bundle to Attack Flow Builder (AFB) format.
    """
    # Layout constants
    HORIZONTAL_SPACING = 430
    VERTICAL_SPACING = 350
    START_X = 100
    START_Y = 100

    objects = stix_bundle.get("objects", [])

    # Categorize STIX objects
    attack_patterns: list[dict] = []
    relationships: list[dict] = []
    infrastructure: list[dict] = []
    malware: list[dict] = []
    threat_actors: list[dict] = []
    tools: list[dict] = []
    courses_of_action: list[dict] = []
    vulnerabilities: list[dict] = []

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type == "attack-pattern":
            attack_patterns.append(obj)
        elif obj_type == "relationship":
            relationships.append(obj)
        elif obj_type == "infrastructure":
            infrastructure.append(obj)
        elif obj_type == "malware":
            malware.append(obj)
        elif obj_type == "threat-actor":
            threat_actors.append(obj)
        elif obj_type == "tool":
            tools.append(obj)
        elif obj_type == "course-of-action":
            courses_of_action.append(obj)
        elif obj_type == "vulnerability":
            vulnerabilities.append(obj)

    # Build flow graph and sort patterns
    flow_graph = build_flow_graph(relationships)
    sorted_patterns = topological_sort(attack_patterns, flow_graph)

    # Create AFB objects
    all_objects: list[dict] = []
    pattern_to_action: dict[str, dict] = {}
    pattern_to_anchors: dict[str, list[dict]] = {}
    layout: dict[str, list[int]] = {}  # instance_id -> [x, y]

    # Track which objects go in flow.objects (not anchors/latches/handles)
    flow_object_ids: list[str] = []

    # Create action objects for each attack pattern
    for i, ap in enumerate(sorted_patterns):
        x = START_X + (i * HORIZONTAL_SPACING)
        y = START_Y
        action, anchor_objs = create_action_object(ap)
        pattern_to_action[ap["id"]] = action
        pattern_to_anchors[ap["id"]] = anchor_objs
        layout[action["instance"]] = [x, y]
        flow_object_ids.append(action["instance"])  # Only action, not anchors
        all_objects.append(action)
        all_objects.extend(anchor_objs)

    # Create asset objects from infrastructure, malware, and tools
    stix_to_asset: dict[str, dict] = {}
    stix_to_asset_anchors: dict[str, list[dict]] = {}
    asset_y = START_Y + VERTICAL_SPACING
    asset_idx = 0

    for infra in infrastructure:
        x = START_X + (asset_idx * HORIZONTAL_SPACING)
        asset, anchor_objs = create_asset_object(infra)
        stix_to_asset[infra["id"]] = asset
        stix_to_asset_anchors[infra["id"]] = anchor_objs
        layout[asset["instance"]] = [x, asset_y]
        flow_object_ids.append(asset["instance"])
        all_objects.append(asset)
        all_objects.extend(anchor_objs)
        asset_idx += 1

    for mal in malware:
        x = START_X + (asset_idx * HORIZONTAL_SPACING)
        asset, anchor_objs = create_asset_object(mal)
        stix_to_asset[mal["id"]] = asset
        stix_to_asset_anchors[mal["id"]] = anchor_objs
        layout[asset["instance"]] = [x, asset_y]
        flow_object_ids.append(asset["instance"])
        all_objects.append(asset)
        all_objects.extend(anchor_objs)
        asset_idx += 1

    for tool in tools:
        x = START_X + (asset_idx * HORIZONTAL_SPACING)
        asset, anchor_objs = create_asset_object(tool)
        stix_to_asset[tool["id"]] = asset
        stix_to_asset_anchors[tool["id"]] = anchor_objs
        layout[asset["instance"]] = [x, asset_y]
        flow_object_ids.append(asset["instance"])
        all_objects.append(asset)
        all_objects.extend(anchor_objs)
        asset_idx += 1

    for vuln in vulnerabilities:
        x = START_X + (asset_idx * HORIZONTAL_SPACING)
        asset, anchor_objs = create_asset_object(vuln)
        stix_to_asset[vuln["id"]] = asset
        stix_to_asset_anchors[vuln["id"]] = anchor_objs
        layout[asset["instance"]] = [x, asset_y]
        flow_object_ids.append(asset["instance"])
        all_objects.append(asset)
        all_objects.extend(anchor_objs)
        asset_idx += 1

    # Create course_of_action objects from STIX courses of action
    stix_to_coa: dict[str, dict] = {}
    stix_to_coa_anchors: dict[str, list[dict]] = {}
    coa_y = START_Y - VERTICAL_SPACING  # Place COAs above actions
    for i, coa in enumerate(courses_of_action):
        x = START_X + (i * HORIZONTAL_SPACING)
        coa_obj, anchor_objs = create_course_of_action_object(coa)
        stix_to_coa[coa["id"]] = coa_obj
        stix_to_coa_anchors[coa["id"]] = anchor_objs
        layout[coa_obj["instance"]] = [x, coa_y]
        flow_object_ids.append(coa_obj["instance"])
        all_objects.append(coa_obj)
        all_objects.extend(anchor_objs)

    # Create connections based on flow graph
    for source_id, targets in flow_graph.items():
        if source_id not in pattern_to_action:
            continue

        source_action = pattern_to_action[source_id]
        source_anchors = pattern_to_anchors[source_id]

        for target_id in targets:
            if target_id not in pattern_to_action:
                continue

            target_action = pattern_to_action[target_id]
            target_anchors = pattern_to_anchors[target_id]

            # Create latches for source (position 90 = right) and target (position 270 = left)
            source_latch_id = generate_uuid()
            target_latch_id = generate_uuid()
            handle_id = generate_uuid()

            # Add latch objects
            all_objects.append({
                "id": "generic_latch",
                "instance": source_latch_id
            })
            all_objects.append({
                "id": "generic_latch",
                "instance": target_latch_id
            })
            all_objects.append({
                "id": "generic_handle",
                "instance": handle_id
            })

            # Create dynamic_line
            line_id = generate_uuid()
            all_objects.append({
                "id": "dynamic_line",
                "instance": line_id,
                "source": source_latch_id,
                "target": target_latch_id,
                "handles": [handle_id]
            })
            flow_object_ids.append(line_id)  # dynamic_lines go in flow.objects

            # Update anchor latches
            # Position "90" is the right anchor (index 3 in positions list)
            # Position "270" is the left anchor (index 9 in positions list)
            source_anchor_id = source_action["anchors"]["90"]
            target_anchor_id = target_action["anchors"]["270"]

            # Find and update the anchor objects
            for anchor in source_anchors:
                if anchor["instance"] == source_anchor_id:
                    anchor["latches"].append(source_latch_id)
                    break

            for anchor in target_anchors:
                if anchor["instance"] == target_anchor_id:
                    anchor["latches"].append(target_latch_id)
                    break

    # Helper function to create a connection between two objects
    def create_object_connection(
        source_obj: dict,
        source_anchors: list[dict],
        target_obj: dict,
        target_anchors: list[dict],
        source_pos: str = "180",  # bottom
        target_pos: str = "0"     # top
    ):
        source_latch_id = generate_uuid()
        target_latch_id = generate_uuid()
        handle_id = generate_uuid()

        all_objects.append({"id": "generic_latch", "instance": source_latch_id})
        all_objects.append({"id": "generic_latch", "instance": target_latch_id})
        all_objects.append({"id": "generic_handle", "instance": handle_id})

        line_id = generate_uuid()
        all_objects.append({
            "id": "dynamic_line",
            "instance": line_id,
            "source": source_latch_id,
            "target": target_latch_id,
            "handles": [handle_id]
        })
        flow_object_ids.append(line_id)

        # Update anchor latches
        source_anchor_id = source_obj["anchors"][source_pos]
        target_anchor_id = target_obj["anchors"][target_pos]

        for anchor in source_anchors:
            if anchor["instance"] == source_anchor_id:
                anchor["latches"].append(source_latch_id)
                break

        for anchor in target_anchors:
            if anchor["instance"] == target_anchor_id:
                anchor["latches"].append(target_latch_id)
                break

    # Build a map of threat-actor relationships for transitive linking
    threat_actor_to_assets: dict[str, list[str]] = {}  # threat-actor -> list of asset IDs
    threat_actor_to_patterns: dict[str, list[str]] = {}  # threat-actor -> list of attack-pattern IDs

    for rel in relationships:
        if rel.get("relationship_type") != "uses":
            continue
        source_ref = rel.get("source_ref", "")
        target_ref = rel.get("target_ref", "")

        if source_ref.startswith("threat-actor--"):
            if target_ref in stix_to_asset:
                if source_ref not in threat_actor_to_assets:
                    threat_actor_to_assets[source_ref] = []
                threat_actor_to_assets[source_ref].append(target_ref)
            elif target_ref in pattern_to_action:
                if source_ref not in threat_actor_to_patterns:
                    threat_actor_to_patterns[source_ref] = []
                threat_actor_to_patterns[source_ref].append(target_ref)

    # Track which assets have been connected to avoid duplicates
    connected_assets: set[str] = set()

    # Create connections between actions and assets (from "uses" relationships)
    for rel in relationships:
        if rel.get("relationship_type") != "uses":
            continue

        source_ref = rel.get("source_ref", "")
        target_ref = rel.get("target_ref", "")

        # Case 1: attack-pattern uses asset (tool/infrastructure/malware)
        if source_ref in pattern_to_action and target_ref in stix_to_asset:
            create_object_connection(
                pattern_to_action[source_ref],
                pattern_to_anchors[source_ref],
                stix_to_asset[target_ref],
                stix_to_asset_anchors[target_ref],
                "180", "0"  # action bottom to asset top
            )
            connected_assets.add(target_ref)
        # Case 2: malware/threat-actor uses asset - connect assets to each other
        elif source_ref in stix_to_asset and target_ref in stix_to_asset:
            create_object_connection(
                stix_to_asset[source_ref],
                stix_to_asset_anchors[source_ref],
                stix_to_asset[target_ref],
                stix_to_asset_anchors[target_ref],
                "90", "270"  # left to right
            )
            connected_assets.add(target_ref)
            connected_assets.add(source_ref)

    # Link assets used by threat-actors to actions used by the same threat-actor
    for ta_id, asset_ids in threat_actor_to_assets.items():
        pattern_ids = threat_actor_to_patterns.get(ta_id, [])
        if not pattern_ids:
            # If no patterns directly linked to threat-actor, use first action
            if sorted_patterns:
                pattern_ids = [sorted_patterns[0]["id"]]

        for asset_id in asset_ids:
            if asset_id in connected_assets:
                continue  # Already connected via direct relationship
            if asset_id not in stix_to_asset:
                continue

            # Connect to first available action from this threat-actor
            for pattern_id in pattern_ids:
                if pattern_id in pattern_to_action:
                    create_object_connection(
                        pattern_to_action[pattern_id],
                        pattern_to_anchors[pattern_id],
                        stix_to_asset[asset_id],
                        stix_to_asset_anchors[asset_id],
                        "180", "0"  # action bottom to asset top
                    )
                    connected_assets.add(asset_id)
                    break  # Only connect to first matching action

    # Connect any remaining unconnected assets to the first action
    if sorted_patterns:
        first_pattern_id = sorted_patterns[0]["id"]
        if first_pattern_id in pattern_to_action:
            for asset_id, asset in stix_to_asset.items():
                if asset_id in connected_assets:
                    continue
                create_object_connection(
                    pattern_to_action[first_pattern_id],
                    pattern_to_anchors[first_pattern_id],
                    stix_to_asset[asset_id],
                    stix_to_asset_anchors[asset_id],
                    "180", "0"
                )
                connected_assets.add(asset_id)

    # Create connections from courses of action to actions/assets (from "mitigates" relationships)
    for rel in relationships:
        if rel.get("relationship_type") != "mitigates":
            continue

        source_ref = rel.get("source_ref", "")
        target_ref = rel.get("target_ref", "")

        # Source must be a course of action
        if source_ref not in stix_to_coa:
            continue

        source_coa = stix_to_coa[source_ref]
        source_anchors = stix_to_coa_anchors[source_ref]

        # Target can be an action (attack-pattern) or asset
        if target_ref in pattern_to_action:
            create_object_connection(
                source_coa,
                source_anchors,
                pattern_to_action[target_ref],
                pattern_to_anchors[target_ref],
                "180", "0"  # COA bottom to action top
            )
        elif target_ref in stix_to_asset:
            create_object_connection(
                source_coa,
                source_anchors,
                stix_to_asset[target_ref],
                stix_to_asset_anchors[target_ref],
                "180", "0"  # COA bottom to asset top
            )

    # Determine flow metadata
    flow_name = "Converted Attack Flow"
    flow_description = "Attack flow converted from STIX bundle"
    author_name = "STIX Converter"

    if threat_actors:
        flow_name = f"{threat_actors[0].get('name', 'Unknown')} Attack Flow"
        flow_description = threat_actors[0].get("description", flow_description)

    # Create the flow (canvas) object
    flow_instance = generate_uuid()
    created_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    flow_object = {
        "id": "flow",
        "instance": flow_instance,
        "properties": [
            ["name", flow_name],
            ["description", flow_description],
            ["author", [
                ["name", author_name],
                ["identity_class", None],
                ["contact_information", ""]
            ]],
            ["scope", "incident"],
            ["external_references", []],
            ["created", created_date]
        ],
        "objects": flow_object_ids  # Only main objects, not anchors/latches/handles
    }

    # Add flow object position to layout
    layout[flow_instance] = [START_X, START_Y + VERTICAL_SPACING * 2]

    # Calculate camera position (center on the flow)
    num_actions = len(sorted_patterns)
    center_x = START_X + (num_actions * HORIZONTAL_SPACING) / 2
    center_y = START_Y + VERTICAL_SPACING

    camera = {
        "x": center_x,
        "y": center_y,
        "k": 0.7  # zoom level
    }

    # Build final AFB structure (key order matters!)
    afb_data = {
        "schema": "attack_flow_v2",
        "theme": "dark_theme",
        "objects": [flow_object] + all_objects,
        "layout": layout,
        "camera": camera
    }

    return afb_data


def validate_stix_bundle(data: dict) -> bool:
    """Basic validation of STIX bundle structure."""
    if data.get("type") != "bundle":
        print("Error: Input is not a STIX bundle (missing 'type': 'bundle')")
        return False

    if "objects" not in data:
        print("Error: Bundle has no 'objects' array")
        return False

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Convert STIX 2.1 JSON to Attack Flow Builder (AFB) format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python stix_to_afb.py attack.stix.json output.afb
    python stix_to_afb.py attack.stix.json  # creates attack.afb
        """
    )
    parser.add_argument(
        "input_file",
        help="Input STIX JSON file path"
    )
    parser.add_argument(
        "output_file",
        nargs="?",
        help="Output AFB file path (default: input filename with .afb extension)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output (default: True)"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate input, don't convert"
    )

    args = parser.parse_args()

    # Determine output filename
    input_path = Path(args.input_file)
    if args.output_file:
        output_path = Path(args.output_file)
    else:
        output_path = input_path.with_suffix(".afb")

    # Read input file
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            stix_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in input file: {e}")
        sys.exit(1)

    # Validate input
    if not validate_stix_bundle(stix_data):
        sys.exit(1)

    if args.validate_only:
        print(f"Validation successful: {input_path}")
        sys.exit(0)

    # Convert
    try:
        afb_data = convert_stix_to_afb(stix_data)
    except Exception as e:
        print(f"Error during conversion: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Write output
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(afb_data, f, indent=4)

        # Print summary
        num_actions = sum(1 for obj in afb_data["objects"] if obj.get("id") == "action")
        num_assets = sum(1 for obj in afb_data["objects"] if obj.get("id") == "asset")
        num_coas = sum(1 for obj in afb_data["objects"] if obj.get("id") == "course_of_action")
        num_lines = sum(1 for obj in afb_data["objects"] if obj.get("id") == "dynamic_line")

        print(f"Conversion successful!")
        print(f"  Input:  {input_path}")
        print(f"  Output: {output_path}")
        print(f"  Actions: {num_actions}")
        print(f"  Assets:  {num_assets}")
        print(f"  Courses of Action: {num_coas}")
        print(f"  Connections: {num_lines}")

    except IOError as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
