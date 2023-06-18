#!/usr/bin/env python3
"""Provides menu options to control the ``pd-ninja`` plugin.
"""
from binaryninja.binaryview import SectionSemantics
from binaryninja.types import Symbol
from binaryninja.types import SymbolType
from binaryninja.plugin import PluginCommand
from binaryninja.log import log_info
from binaryninja.log import log_error
from binaryninja.binaryview import BinaryView
from binaryninja.typeparser import TypeParser

from .pd_magic import IVT_LEN
from .pd_magic import PD_HEADER_FLAGS
from .pd_magic import PLAYDATE_KERNEL_START
from .pd_magic import STM32F7_IVT_NAMES
from .pd_magic import get_system_headers
from .pd_utils import get_sdk_root
from .pd_utils import addr_valid
from .pd_utils import dest_section
from .pd_types import make_stable_library
from .pd_symbols_db import SymbolsDB


def apply_symbols_db(bv: BinaryView):
    """Loads provided symbols from the SDK

    Parameters
    ----------
    bv : BinaryView
        SDK to process
    """
    pd_sdk = get_sdk_root()
    if not pd_sdk:
        log_info("Failed to provide SDK path")
        return

    thumb_addr_mask = 0xFFFFFFFE
    s = SymbolsDB(pd_sdk.symbols_db)
    log_info(f"Loading symbols from symbols.db")

    # note the omission of "strip_hideen=True", we postprocess here
    # and define an auto-function where all the hidden functions are
    # so binary ninja can still pick up all the functions to analyze
    funcs = s.get_first_functions()

    # make all these definitions 1 undo just in case
    # somthing is real borked up
    bv.begin_undo_actions()

    # add all the symbols, playdate calls them functions, which is
    # patently false, they're just a bunch of linker symbols
    for f in funcs:
        # don't need to worry about any kernel / user distinctions here
        if not addr_valid(bv, f.address):
            continue

        section = dest_section(bv, f.address)
        address = f.address & thumb_addr_mask

        # depending on the semantics of the section we will create
        # different symbol type
        if section.semantics & SectionSemantics.ReadOnlyCodeSectionSemantics:
            # code, define a function
            if f.name == "hidden":
                bv.define_auto_symbol_and_var_or_function(
                    Symbol(SymbolType.FunctionSymbol, address,
                           f"sub_{hex(address)[2:]}"), None
                )
            else:
                # not "hidden", so make an actual function
                bv.create_user_function(address)
                bv.define_user_symbol(
                    Symbol(SymbolType.FunctionSymbol, address, f.name))
        else:
            # data
            if f.name == "hidden":
                bv.define_auto_symbol_and_var_or_function(
                    Symbol(SymbolType.DataSymbol, address,
                           f"data_{hex(address)[2:]}"), None
                )
            else:
                # not hidden, add a label with words, note that
                # the types are not specified, a lot of them are defined
                # in the ``make_yolo_library()`` calls in ``pd_magic`` tho
                bv.define_user_symbol(
                    Symbol(SymbolType.DataSymbol, address, f.name))

    log_info(f"Added {len(funcs)} labels from Symbols.db")
    bv.commit_undo_actions()


def import_sdk_header(bv: BinaryView):
    """Imports the types from the C_API header into
    the current binary view

    Parameters
    ----------
    bv : BinaryView
        bv to load the types into
    """
    pd_sdk = get_sdk_root()
    if not pd_sdk:
        log_info("Failed to provide SDK path")
        return

    # import the header file for the playdate SDK
    with open(str(pd_sdk.header_path), "r") as f:
        flags = PD_HEADER_FLAGS["flags"]
        include_path = [str(pd_sdk.root / "C_API")]
        sys_include_path = get_system_headers()
        defines = PD_HEADER_FLAGS["defines"]

        parsed = TypeParser.default.parse_types_from_source(
            f.read(),
            pd_sdk.header_path.name,
            bv.platform,
            None,
            flags + defines,
            include_path + sys_include_path)

        types = parsed[0].types
        functions = parsed[0].functions

        if parsed is None:
            log_error("Failed parsing header file")
            return

        # add the functions and types so we can actually use them
        for t in types:
            bv.define_user_type(t.name, t.type)

        for f in functions:
            bv.define_user_type(f.name, f.type)

        log_info(
            f"pd-ninja Loaded {len(types)} types, {len(functions)} functions.")

    # add the stablized types
    make_stable_library(bv)


def add_platform_symbols(bv: BinaryView):
    """Adds platform symbols to the binaryview

    Parameters
    ----------
    bv : BinaryView
        bv to modify
    """
    # if we have a dump that contains the kernel + bootlaoder, tag the IVT
    log_info("Adding IVT Table")
    # apply IVT Type
    ivt_type = bv.get_type_by_name("IVT_TABLE")
    if not ivt_type:
        log_error("Must add pd-ninja types first!")
        return

    bv.define_user_data_var(PLAYDATE_KERNEL_START, ivt_type)
    bv.define_user_symbol(
        Symbol(SymbolType.DataSymbol,
               PLAYDATE_KERNEL_START, "ivt_table")
    )

    # the first value in the IVT is the stack pointer, not a pointer
    thumb_addr_mask = 0xFFFFFFFE  # binary ninja is bad at thumb
    ivt_labels_start = PLAYDATE_KERNEL_START + 4
    ivt_labels_end = ivt_labels_start + (IVT_LEN - 4)
    for i, addr in enumerate(range(ivt_labels_start, ivt_labels_end, 4)):
        # this iterator starts from 1 idx
        name = STM32F7_IVT_NAMES[i + 1]
        value = bv.read_int(addr, 4, False) & thumb_addr_mask
        bv.define_auto_symbol(
            Symbol(SymbolType.FunctionSymbol, value, name))

    log_info("Added IVT_TABLE and created appropriate function pointers")


def apply_stabilized_types(bv: BinaryView):
    """Applies known types to known symbols. TODO

    Parameters
    ----------
    bv : BinaryView
        bv to modify
    """


def register_plugin():
    PluginCommand.register("pd-ninja\Load Symbols.db",
                           "Load symbols.db from the SDK",
                           apply_symbols_db)

    PluginCommand.register("pd-ninja\Import C_API/pd_api.h",
                           "Load PD types from SDK",
                           import_sdk_header)
    PluginCommand.register("pd-ninja\Add Platform Symbols",
                           "Add symbols for the STM32F746IE",
                           add_platform_symbols)
