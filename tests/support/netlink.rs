const NLA_F_NESTED: u16 = 0x8000;

pub(crate) fn attr(nla_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NLA_HDRLEN + payload.len() + NLA_ALIGNTO - 1);
    let len = u16::try_from(NLA_HDRLEN + payload.len()).expect("attribute fits in u16");
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&nla_type.to_ne_bytes());
    out.extend_from_slice(payload);
    while out.len() % NLA_ALIGNTO != 0 {
        out.push(0);
    }
    out
}

pub(crate) fn nested(nla_type: u16, children: &[Vec<u8>]) -> Vec<u8> {
    attr(nla_type | NLA_F_NESTED, &children.concat())
}

pub(crate) fn tuple(
    nla_type: u16,
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    sport: u16,
    dport: u16,
) -> Vec<u8> {
    nested(
        nla_type,
        &[
            nested(
                CTA_TUPLE_IP,
                &[attr(CTA_IP_V4_SRC, &src), attr(CTA_IP_V4_DST, &dst)],
            ),
            nested(
                CTA_TUPLE_PROTO,
                &[
                    attr(CTA_PROTO_NUM, &[proto]),
                    attr(CTA_PROTO_SRC_PORT, &sport.to_be_bytes()),
                    attr(CTA_PROTO_DST_PORT, &dport.to_be_bytes()),
                ],
            ),
        ],
    )
}

pub(crate) fn counters(nla_type: u16, packets: u64, bytes: u64) -> Vec<u8> {
    nested(
        nla_type,
        &[
            attr(CTA_COUNTERS_PACKETS, &packets.to_be_bytes()),
            attr(CTA_COUNTERS_BYTES, &bytes.to_be_bytes()),
        ],
    )
}

pub(crate) fn message(nlmsg_type: u16, family: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![family, 0, 0, 0];
    body.extend_from_slice(&attrs.concat());

    let mut out = Vec::with_capacity(NLMSG_HDRLEN + body.len());
    let len = u32::try_from(NLMSG_HDRLEN + body.len()).expect("message fits in u32");
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&nlmsg_type.to_ne_bytes());
    out.extend_from_slice(&0u16.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&body);
    while out.len() % NLA_ALIGNTO != 0 {
        out.push(0);
    }
    out
}

pub(crate) fn ct_event(msg_type: u8, family: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    message(
        (NFNL_SUBSYS_CTNETLINK << 8) | u16::from(msg_type),
        family,
        attrs,
    )
}
