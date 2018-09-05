Introduction
============

This tool is a generic dissector that was originally created to dissect QUIC_ packets but that can also be used for many
purposes. The dissector is decoupled from the protocol definition and provides a dedicated syntax to specify its wire
image. The tool operates on a per-packet basis, taking in the packet content as a sequence of bytes and outputting an
abstract representation of the packet content. This representation is an annotation of the byte sequence that labels the
fields and structures defined in the protocol definition, together with the values extracted from the byte sequence.


.. _QUIC: https://quicwg.org/