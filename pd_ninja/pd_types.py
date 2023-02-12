#!/usr/bin/env python3
from binaryninja.types import Type
from binaryninja.types import StructureBuilder
from binaryninja.binaryview import BinaryView

from .pd_magic import STM32F7_IVT_NAMES


def make_vector_table(bv: BinaryView) -> None:
    """Constructs a Vector Table Type

    Parameters
    ----------
    bv : BinaryView
        context to add to
    """
    # why doesn'
    with StructureBuilder.builder(bv, "IVT_TABLE") as struct:
        struct.append(Type.int(4, False), STM32F7_IVT_NAMES[0])

        # add the remainder of the struct, they are all pointers
        for name in STM32F7_IVT_NAMES[1:]:
            struct.append(Type.pointer(bv.arch, Type.function()), name)


def make_stable_library(bv: BinaryView):
    """Wrapped behind a function so this can both import pd_magic
    and be referenced by it.
    """

    # make ivt
    make_vector_table(bv)


def make_yolo_library():
    pass
