use rstest::rstest;

#[rstest]
#[case(&[0], 65535)]
#[case(&[0, 0], 65535)]
// #[case(&[0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xc0, 0xa8, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0xc7], 0xb862)]
fn test_checksum_func(#[case] input_buf: &[u8], #[case] expected: u16) {
    assert_eq!(super::icmp::calc_checksum(input_buf), expected)
}
