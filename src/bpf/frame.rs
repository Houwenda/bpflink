use crate::{Error, Result};

const BPF_WORD_SIZE: usize = std::mem::size_of::<i32>();
const MIN_BPF_HDR_LEN: usize = 18;
const CAPLEN_OFFSET: usize = 8;
const HDRLEN_OFFSET: usize = 16;

pub(crate) fn iter_bpf_frames(buf: &[u8]) -> BpfFrameIter<'_> {
    BpfFrameIter { buf, offset: 0 }
}

pub(crate) struct BpfFrameIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for BpfFrameIter<'a> {
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.buf.len() {
            return None;
        }

        if self.buf.len().saturating_sub(self.offset) < MIN_BPF_HDR_LEN {
            self.offset = self.buf.len();
            return Some(Err(Error::PacketParse("truncated bpf header")));
        }

        let header_start = self.offset;
        let caplen = read_u32(self.buf, header_start + CAPLEN_OFFSET) as usize;
        let hdrlen = read_u16(self.buf, header_start + HDRLEN_OFFSET) as usize;

        if hdrlen < MIN_BPF_HDR_LEN {
            self.offset = self.buf.len();
            return Some(Err(Error::PacketParse("invalid bpf header length")));
        }

        let frame_start = match header_start.checked_add(hdrlen) {
            Some(value) => value,
            None => {
                self.offset = self.buf.len();
                return Some(Err(Error::PacketParse("bpf frame offset overflow")));
            }
        };
        let frame_end = match frame_start.checked_add(caplen) {
            Some(value) => value,
            None => {
                self.offset = self.buf.len();
                return Some(Err(Error::PacketParse("bpf frame length overflow")));
            }
        };

        if frame_end > self.buf.len() {
            self.offset = self.buf.len();
            return Some(Err(Error::PacketParse("truncated bpf frame")));
        }

        self.offset = bpf_word_align(frame_end);
        if self.offset > self.buf.len() {
            self.offset = self.buf.len();
        }

        Some(Ok(&self.buf[frame_start..frame_end]))
    }
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        buf[offset..offset + 4]
            .try_into()
            .expect("slice length checked"),
    )
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes(
        buf[offset..offset + 2]
            .try_into()
            .expect("slice length checked"),
    )
}

fn bpf_word_align(value: usize) -> usize {
    (value + (BPF_WORD_SIZE - 1)) & !(BPF_WORD_SIZE - 1)
}

#[cfg(test)]
mod tests {
    use super::iter_bpf_frames;

    const HDR_LEN: usize = 18;

    fn push_header(buf: &mut Vec<u8>, caplen: u32, datalen: u32, hdrlen: u16) {
        buf.extend_from_slice(&0i32.to_ne_bytes());
        buf.extend_from_slice(&0i32.to_ne_bytes());
        buf.extend_from_slice(&caplen.to_ne_bytes());
        buf.extend_from_slice(&datalen.to_ne_bytes());
        buf.extend_from_slice(&hdrlen.to_ne_bytes());
    }

    fn align(value: usize) -> usize {
        (value + 3) & !3
    }

    #[test]
    fn bpf_frame_iterates_multiple_frames_with_padding() {
        let mut buf = Vec::new();
        push_header(&mut buf, 3, 3, HDR_LEN as u16);
        buf.extend_from_slice(&[1, 2, 3]);
        buf.resize(align(buf.len()), 0);
        push_header(&mut buf, 4, 4, HDR_LEN as u16);
        buf.extend_from_slice(&[4, 5, 6, 7]);

        let frames = iter_bpf_frames(&buf)
            .map(|frame| frame.map(|bytes| bytes.to_vec()))
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(frames, vec![vec![1, 2, 3], vec![4, 5, 6, 7]]);
    }

    #[test]
    fn bpf_frame_uses_darwin_bpf_word_alignment_between_records() {
        let mut buf = Vec::new();
        push_header(&mut buf, 2, 2, HDR_LEN as u16);
        buf.extend_from_slice(&[1, 2]);
        buf.resize(20, 0);
        push_header(&mut buf, 3, 3, HDR_LEN as u16);
        buf.extend_from_slice(&[3, 4, 5]);

        let frames = iter_bpf_frames(&buf)
            .map(|frame| frame.map(|bytes| bytes.to_vec()))
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(frames, vec![vec![1, 2], vec![3, 4, 5]]);
    }

    #[test]
    fn bpf_frame_rejects_truncated_header_or_frame() {
        let short_header = vec![0; HDR_LEN - 1];
        let err = iter_bpf_frames(&short_header).next().unwrap().unwrap_err();
        assert!(matches!(err, crate::Error::PacketParse(_)));

        let mut short_frame = Vec::new();
        push_header(&mut short_frame, 8, 8, HDR_LEN as u16);
        short_frame.extend_from_slice(&[1, 2, 3]);
        let err = iter_bpf_frames(&short_frame).next().unwrap().unwrap_err();
        assert!(matches!(err, crate::Error::PacketParse(_)));
    }
}
