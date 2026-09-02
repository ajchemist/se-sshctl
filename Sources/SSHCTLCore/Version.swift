/// The released version of this tool.
///
/// Kept as a literal rather than derived from git so that a binary built from
/// a tarball, a tag, or a working tree all answer the same way. The release
/// workflow refuses to publish a tag whose value here does not match it, so a
/// binary cannot claim a version it was not built for.
public let seSSHCTLVersion = "0.3.0"
