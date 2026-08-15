def get_correlation_graph(domain: str) -> dict:
    """Builds simple node/edge data for the IOC correlation graph on the
    result page. Returns {"nodes": [...], "edges": [...]} where each node
    has id/label/kind (center|domain|ip|asn) and kind drives SVG color in
    the template. Center node is the scanned domain; edges connect it to
    any IP/ASN it shares with previously-scanned domains, and those other
    domains hang off the shared IP/ASN node."""
    from models import IocRecord, ScanHistory

    center = {"id": domain, "label": domain, "kind": "center"}
    nodes = {domain: center}
    edges = []

    own_records = IocRecord.query.filter_by(domain=domain).order_by(IocRecord.recorded_at.desc()).all()
    if not own_records:
        return {"nodes": [center], "edges": []}

    seen_ips = {r.ip for r in own_records if r.ip}
    seen_asns = {r.asn for r in own_records if r.asn}

    for ip in seen_ips:
        ip_node_id = f"ip:{ip}"
        nodes[ip_node_id] = {"id": ip_node_id, "label": ip, "kind": "ip"}
        edges.append({"source": domain, "target": ip_node_id})

        others = (
            IocRecord.query
            .filter(IocRecord.ip == ip, IocRecord.domain != domain)
            .all()
        )
        for rec in others:
            other_id = rec.domain
            if other_id not in nodes:
                last_scan = (
                    ScanHistory.query
                    .filter(ScanHistory.input_data.like(f"%{other_id}%"))
                    .order_by(ScanHistory.created_at.desc())
                    .first()
                )
                is_dangerous = bool(last_scan and last_scan.verdict and last_scan.verdict.lower() == "dangerous")
                nodes[other_id] = {
                    "id": other_id,
                    "label": other_id,
                    "kind": "dangerous_domain" if is_dangerous else "domain",
                }
            edges.append({"source": ip_node_id, "target": other_id})

    for asn in seen_asns:
        asn_node_id = f"asn:{asn}"
        rec_with_desc = next((r for r in own_records if r.asn == asn), None)
        asn_label = rec_with_desc.asn_description if rec_with_desc and rec_with_desc.asn_description else asn
        nodes[asn_node_id] = {"id": asn_node_id, "label": asn_label, "kind": "asn"}
        edges.append({"source": domain, "target": asn_node_id})

    return {"nodes": list(nodes.values()), "edges": edges}
