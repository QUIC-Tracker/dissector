Protocol specification
======================

The dissector is able to choose from several protocols when dissecting a packet. Each of them is defined in a YAML file
found in the protocols directory. A protocol description allows to define the set of messages that can be exchanged by
the peers and how it can be parsed. The dissector choose the protocol that is able to dissect the entire
packet received without raising a ``ParseError``.

Introduction to structures
--------------------------

The basic unit for describing a message is a *structure*. A protocol YAML file defines all the structures that can
appear in this protocol as well as how they interact with each other, i.e. which ones can include others and which ones
only appears before or after particular structures. Each *structure* can contain several fields. For each field, a
number of parameters that describe how to parse it can be specified. For now, let's consider the most basic one:
``length``. It allows to specify the length of the field in bits. With these two notions we can define a first
structure.

.. highlight:: yaml

::

    Structure A:
      - First Field:
          length: 32

.. note::
    Indentation is semantic in YAML. Double check it when a file cannot be parsed or the dissector is behaving
    incorrectly.

This structure is named ``Structure A`` and contains a single 4-byte long field ``First field``. Using this description,
the dissector is able to parse this structure. But there is currently no indication where it should expect this
structure to appear. Structures can either appear in other structures, or at the beginning of a packet. To specify
that ``Structure A`` only appears once at the beginning of a packet, we must include it in the list of
*top structures*.

::

    top:
      - Structure A

    Structure A:
      - First Field:
          length: 32

If we want the structure to be followed by itself until the packet ends, we can specify it as the next structure.

::

    top:
      - Structure A

    Structure A:
      - First Field:
          length: 32
      - next: Structure A

A field can be restricted to only allow particular values. Network protocols usually include a marker to distinguish
different types of messages. The field attribute ``values`` can be used for that purpose. Let's introduce another
structure that only contains a 4-byte long value of 42.

::

    top:
      - Structure A
      - Structure B

    Structure A:
      - First Field:
          length: 32
      - next: Structure A

    Structure B:
      - First Field:
          length: 32
          values: 42  # Equivalent to values: [42] or values:
                      #                                 eq: 42
      - next: Structure B

If the protocol allows both structures to repeatedly appear in a message, we can define a common type for both. The
dissector tries one of the structure that corresponds to the type and if a failure is encountered, e.g. because one
value does not match the field requirements, the dissector backtracks to another structure.

::

    top:
      - Structures

    Structure A:
      - type: Structures
      - First Field:
          length: 32
      - next: Structures

    Structure B:
      - type: Structures
      - First Field:
          length: 32
          values: 42
      - next: Structures

Structures can be embedded into other structures using the ``parse`` parameter. A structure type or a structure name can
be given as argument. Let's consider a protocol in which the two structure previously can be embedded into a
bigger structure, ``Big Structure``.

::

    top:
      - Big Structure

    Big Structure:
      - Structures Length:
          length: 8
          triggers:
            - Some Structures:
                length: set
      - Some Structures:
          parse: Structures

    Structure A:
      - type: Structures
      - First Field:
          length: 32

    Structure B:
      - type: Structures
      - First Field:
          length: 32
          values: 42

The ``Big Structure`` defines two fields, the first is a single byte that define how many structures should be
parsed when parsing the second field using the ``length`` parameter. One can also specify how many bytes should be
parsed using the ``byte_length`` parameter.

Complete syntax reference
-------------------------

Each top-level key defines a new structure in the protocol. The ``top`` key is a reserved key that defines which
structures can appear at the beginning of a packet.


Structure
+++++++++

A structure defines a list of fields. ``type`` and ``next`` are reserved keywords that cannot be used as field name.

- ``type`` -- indicates to which type this structure belongs to. Structure types can be used as value for any parameter
  that expects a structure name as argument.
- ``next`` -- defines which structure can follow the current structure. This is an indication and not a strict
  requirement. It should be used when the current structure can be repeatedly embedded into another structure until the
  buffer ends.

Fields
++++++

Each field can specify the following parameters.

- ``length`` -- indicates how many **bits** should be parsed when parsing this field. Failing to extract the given
  amount of bits raises a ``ParseError``. It can also accept special values:
    - ``'*'`` -- indicates that the field spans the rest of the buffer.
    - ``varint`` -- indicates that the field contains a QUIC varint.
    - ``pn`` -- indicates that the field contains a QUIC packet number.

- ``byte_length`` -- indicates how many **bytes** should be parsed when parsing this field. Note that ``length`` is used
  if both are present. It does not accept other special values on the contrary.

- ``format`` -- indicates how the value extracted should be formatted. Accepted values are the Python builtin types
  names (e.g. ``bytes`` or ``hex``, defaults to ``int`` for fields up to 64 bits and ``bytes`` otherwise)

- ``values`` -- defines a value, a list of value or a condition that should be respected for the field to be
  successfully parsed. A condition is an operator (``eq`` or ``neq``).

- ``conditions`` -- defines a list of conditions that should be respected for this field to appear in the structure. A
  condition is a field name inside the current structure, an operator (``eq`` or ``neq``) and a value. If one of the
  condition is not respected, the field will be omitted when parsing the structure. Conditions are evaluated every time
  the field should be parsed.

.. note::

    Encountering a failure in ``conditions`` skips the field and continue the current structure parsing. Encountering a
    failure in ``values`` makes the entire structure parsing fail.

- ``triggers`` -- defines a list of actions that should be taken when the field has been successfully parsed. An action
  can alter the definition a field of the current structure, e.g. set the length of the next field. An action is a field
  name inside the current structure, a field parameter and a value. The value can be a single value or a dictionary. The
  dictionary will be used to map the value of the current field to the value that will be given to the action parameter.
  The special value ``set`` indicate that the action parameter takes the value of the current field.

.. note::

    When an action specify the field ``length`` as target and the value ``set``, the ``length`` considers the value as a
    number of **bytes**, i.e. multiplied by 8, rather than **bits**. This behaviour is deprecated and ``byte_length``
    should be used instead for that purpose.

- ``fallback`` -- defines alternative field parameters that are used in case of a failure when parsing the field.

- ``repeated`` -- takes a null value and indicates that the field should be parse repeatedly until the buffer ends. This
  is a lighter alternative to defining a separate structure with a single field.


Dissector output
----------------

The dissector outputs its result as a list of tuples. Structure and field are represented as tuples. Each tuple has the
form :math:`(name, value, start_{off}, end{off})`. The :math:`name` is the name of the structure or field.
:math:`start_{off}` and :math:`end{off}` are the offset in the payload the value is spanning. The :math:`value` itself
can be a tuple or a list of tuples, or a value extracted from the payload (of type ``int``, ``bytes``, ``str``, ...).
The :math:`value` of fields is a tuple or an extracted value. Structures always have a list of tuples as :math:`value`.