#[cfg(target_os = "macos")]
pub(crate) mod macos {
    pub(crate) const BIOCGBLEN: libc::c_ulong = libc::BIOCGBLEN;
    pub(crate) const BIOCSETIF: libc::c_ulong = libc::BIOCSETIF;
    pub(crate) const BIOCIMMEDIATE: libc::c_ulong = libc::BIOCIMMEDIATE;
    pub(crate) const BIOCPROMISC: libc::c_ulong = libc::BIOCPROMISC as libc::c_ulong;
    pub(crate) const BIOCSHDRCMPLT: libc::c_ulong = libc::BIOCSHDRCMPLT;
    pub(crate) const BIOCSSEESENT: libc::c_ulong = libc::BIOCSSEESENT;
    pub(crate) const BIOCSETF: libc::c_ulong = libc::BIOCSETF;

    #[cfg(test)]
    mod tests {
        #[test]
        fn bpf_ioctl_constants_match_libc() {
            assert_eq!(super::BIOCGBLEN, libc::BIOCGBLEN);
            assert_eq!(super::BIOCSETIF, libc::BIOCSETIF);
            assert_eq!(super::BIOCIMMEDIATE, libc::BIOCIMMEDIATE);
            assert_eq!(super::BIOCPROMISC, libc::BIOCPROMISC as libc::c_ulong);
            assert_eq!(super::BIOCSHDRCMPLT, libc::BIOCSHDRCMPLT);
            assert_eq!(super::BIOCSSEESENT, libc::BIOCSSEESENT);
            assert_eq!(super::BIOCSETF, libc::BIOCSETF);
        }
    }
}
