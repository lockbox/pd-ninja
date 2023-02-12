#!/usr/bin/env python3
"""Loads a custom BinaryView for the Playdate Console
"""
from enum import Enum
from pathlib import Path

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView, SectionSemantics, SegmentFlag
from binaryninja.interaction import get_choice_input
from binaryninja.interaction import get_directory_name_input
from binaryninja.log import log_info
from binaryninja.log import log_error
from binaryninja.types import Symbol, SymbolType
from binaryninja.typeparser import TypeParser
from binaryninja.typelibrary import TypeLibrary
from binaryninja.binaryview import Section

# import necessary magic things to look for
from .pd_magic import make_yolo_library
from .pd_magic import make_stable_library
from .pd_magic import get_system_headers
from .pd_magic import PD_HEADER_FLAGS
from .pd_magic import KERNEL_TOKEN_LIST
from .pd_magic import PLAYDATE_KERNEL_START
from .pd_magic import PLAYDATE_RAM_START
from .pd_magic import PLAYDATE_RAM_SIZE
from .pd_magic import IVT_LEN
from .pd_magic import PLAYDATE_MEM_START
from .pd_magic import PLAYDATE_USER_SIZE
from .pd_magic import PLAYDATE_USER_END
from .pd_magic import PLAYDATE_KERNEL_END
from .pd_magic import PLAYDATE_USER_START
from .pd_magic import STM32F7_IVT_NAMES
from .pd_magic import STM32F7_SRAM_REGIONS
from .pd_magic import PLAYDATE_KERNEL_SIZE
from .pd_magic import PLAYDATE_MEM_SIZE
from .pd_magic import PLAYDATE_ROUGH_USER_SIZE
from .pd_magic import USER_TOKEN_LIST
from .pd_magic import PLAYDATE_USER_DATA_SEARCH_START

from .pd_symbols_db import SymbolsDB


class PDViewType(Enum):
    """Used to specify the type of view this is so segment creation doesn't
    get all jacked up.

    Used in view validation to help see if the current view should be
    loaded by the Playdate or not.
    """
    USER = 0
    KERNEL = 1
    FULL = 2
    INVALID = 0xF


PD_VIEW_TO_BASE_ADDR = {
    PDViewType.USER: PLAYDATE_USER_START,
    PDViewType.FULL: PLAYDATE_MEM_START,
    PDViewType.KERNEL: PLAYDATE_KERNEL_START,
}


class PlayDateView(BinaryView):
    name = "Playdate Firmware"
    long_name = "Playdate Firmware Memory Dump"

    def __init__(self, data: BinaryView):
        self.raw = data
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture["thumb2"].standalone_platform
        self.pd_view_type: PDViewType = PDViewType.INVALID
        self.pd_mem_size: int = 0

    def create_sections(self):
        # add the proper semantic sections on top of the data segments

        if self.pd_view_type in [PDViewType.FULL, PDViewType.KERNEL]:
            # add IVT section
            self.add_user_section("IVT", PLAYDATE_KERNEL_START, IVT_LEN,
                                  SectionSemantics.ReadWriteDataSectionSemantics)

            # add section for kernel space - for now just do one section
            # since there's a bunch of data thrown everywhere  probably bc
            # i thnk it holds the data for both the bootloader and the kernel
            self.add_user_section("KERNEL", PLAYDATE_KERNEL_START + IVT_LEN, PLAYDATE_KERNEL_SIZE - IVT_LEN,
                                  SectionSemantics.ReadOnlyDataSectionSemantics | SectionSemantics.ReadOnlyCodeSectionSemantics)
        # RAM
        self.add_user_section("RAM", PLAYDATE_RAM_START, PLAYDATE_RAM_SIZE,
                              SectionSemantics.ReadWriteDataSectionSemantics)

        # user RO code
        user_code_len = self.find_user_data_start(PLAYDATE_KERNEL_SIZE)
        self.add_user_section("Usermode Code", PLAYDATE_USER_START,
                              user_code_len, SectionSemantics.ReadOnlyCodeSectionSemantics)

        # user RO data
        user_data_start = PLAYDATE_USER_START + user_code_len
        self.add_user_section("Usermode Data", user_data_start, PLAYDATE_USER_END -
                              user_data_start, SectionSemantics.ReadOnlyDataSectionSemantics)

    def create_segments(self):
        # add SRAM regions
        for region in STM32F7_SRAM_REGIONS:
            log_info(f"adding region: {region}")
            length = region.end - region.start
            self.add_auto_segment(region.start, length, 0, 0, SegmentFlag.SegmentReadable |
                                  SegmentFlag.SegmentWritable)

        # add kernel segment
        if self.pd_view_type in [PDViewType.FULL, PDViewType.KERNEL]:
            self.add_auto_segment(PLAYDATE_KERNEL_START, PLAYDATE_KERNEL_SIZE, 0, PLAYDATE_KERNEL_SIZE, SegmentFlag.SegmentContainsCode |
                                  SegmentFlag.SegmentContainsData | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
            user_fbase = PLAYDATE_KERNEL_SIZE
        else:
            user_fbase = 0

        # create user segment
        self.add_auto_segment(PLAYDATE_USER_START, PLAYDATE_USER_SIZE, user_fbase, PLAYDATE_MEM_SIZE, SegmentFlag.SegmentContainsCode |
                              SegmentFlag.SegmentContainsData | SegmentFlag.SegmentDenyWrite | SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

    def find_user_data_start(self, start: int) -> int:
        """returns offset into the binaryview that user data starts at"""
        data = self.raw.read(start, self.pd_mem_size)
        offset = data.find(b" deviceRegistrationChanged")  # ~ majick ~
        return offset - 1

    def add_symbols(self):
        # if we have a dump that contains the kernel + bootlaoder, tag the IVT
        if self.pd_view_type in [PDViewType.FULL, PDViewType.KERNEL]:
            # apply IVT Type
            ivt_type = self.get_type_by_name("IVT_TABLE")
            self.define_user_data_var(PLAYDATE_KERNEL_START, ivt_type)
            self.define_user_symbol(
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
                value = self.read_int(addr, 4, False) & thumb_addr_mask
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, value, name))

        # apply labels from the symbols db
        self.apply_symbols_db()

        # apply types from header to functions
        self.apply_pd_types()

        # set entry
        if self.pd_view_type in [PDViewType.FULL, PDViewType.KERNEL]:
            entry_symbol = self.get_symbol_by_raw_name(STM32F7_IVT_NAMES[1])
            self.add_entry_point(entry_symbol.address & thumb_addr_mask)
        else:
            self.add_entry_point(PLAYDATE_USER_START)

    def apply_pd_types(self):
        pass

    def addr_valid(self, addr: int) -> bool:
        for r in [(s.start, s.end) for s in self.segments]:
            if addr >= r[0] and addr < r[1]:
                return True
        return False

    def dest_section(self, addr: int) -> Section:
        """Returns the corresponding section that an address
        is a member of.

        Parameters
        ----------
        addr : int
            address to check

        Returns
        -------
        Section
            parent section
        """
        for sec in self.sections.values():
            if addr >= sec.start and addr < sec.end:
                return sec
        raise ValueError(f"No section containing address: {addr}")

    def apply_symbols_db(self):
        thumb_addr_mask = 0xFFFFFFFE
        s = SymbolsDB(self.pd_symbols_path)
        log_info(f"Loading symbols from symbols.db")

        # note the omission of "strip_hideen=True", we postprocess here
        # and define an auto-function where all the hidden functions are
        # so binary ninja can still pick up all the functions to analyze
        funcs = s.get_first_functions()

        # make all these definitions 1 undo just in case
        # somthing is real borked up
        self.begin_undo_actions()

        # add all the symbols, playdate calls them functions, which is
        # patently false, they're just a bunch of linker symbols
        for f in funcs:
            # don't need to worry about any kernel / user distinctions here
            if not self.addr_valid(f.address):
                continue

            section = self.dest_section(f.address)
            address = f.address & thumb_addr_mask

            # depending on the semantics of the section we will create
            # different symbol type
            if section.semantics & SectionSemantics.ReadOnlyCodeSectionSemantics:
                # code, define a function
                if f.name == "hidden":
                    self.define_auto_symbol_and_var_or_function(
                        Symbol(SymbolType.FunctionSymbol, address,
                               f"sub_{hex(address)[2:]}"), None
                    )
                else:
                    # not "hidden", so make an actual function
                    self.create_user_function(address)
                    self.define_user_symbol(
                        Symbol(SymbolType.FunctionSymbol, address, f.name))
            else:
                # data
                if f.name == "hidden":
                    self.define_auto_symbol_and_var_or_function(
                        Symbol(SymbolType.DataSymbol, address,
                               f"data_{hex(address)[2:]}"), None
                    )
                else:
                    # not hidden, add a label with words, note that
                    # the types are not specified, a lot of them are defined
                    # in the ``make_yolo_library()`` calls in ``pd_magic`` tho
                    self.define_user_symbol(
                        Symbol(SymbolType.DataSymbol, address, f.name))

        log_info(f"Added {len(funcs)} labels from Symbols.db")
        self.commit_undo_actions()

    def perform_get_entry_point(self) -> int:
        if self.pd_view_type in [PDViewType.FULL, PDViewType.KERNEL]:
            # return 0x80001c8
            thumb_addr_mask = 0xFFFFFFFE
            entry_symbol = self.get_symbol_by_raw_name(STM32F7_IVT_NAMES[1])
            return entry_symbol.address & thumb_addr_mask
        else:
            # user
            return PLAYDATE_USER_START

    def get_sdk_root(self) -> bool:
        pd_path = get_directory_name_input("Path to PlaydateSDK:")

        if not pd_path:
            return False

        p = Path(pd_path)
        if not p.exists():
            log_error("invalid path")
            return False

        if not p.is_dir():
            log_error("not a directory")
            return False

        self.pd_sdk_root = p
        self.pd_symbols_path = p / "bin" / "symbols.db"
        self.pd_header_path = p / "C_API" / "pd_api.h"

        if not self.pd_header_path.exists() or not self.pd_header_path.is_file():
            log_error(
                f"Could not find file for header at {self.pd_header_path}")

        if not self.pd_symbols_path.exists() or not self.pd_symbols_path.is_file():
            log_error(
                f"Could not find file for header at {self.pd_symbols_path}")

        return True

    def add_core_pd_types(self):
        """Adds types from the `pd_api.h` header file shipped with the SDK,
        various other SDK Playdate uses, and RE types that have stabilized.
        """
        # import the header file for the playdate SDK
        with open(str(self.pd_header_path.absolute()), "r") as f:
            flags = PD_HEADER_FLAGS["flags"]
            include_path = [str(self.pd_sdk_root / "C_API")]
            sys_include_path = get_system_headers()
            defines = PD_HEADER_FLAGS["defines"]

            parsed = TypeParser.default.parse_types_from_source(
                f.read(),
                self.pd_header_path.name,
                self.platform,
                None,
                flags + defines,
                include_path + sys_include_path)

            types = parsed[0].types
            functions = parsed[0].functions

            # add the functions and types so we can actually use them
            for t in types:
                self.define_user_type(t.name, t.type)

            for f in functions:
                self.define_user_type(f.name, f.type)

            log_info(
                f"pd-ninja Loaded {len(types)} types, {len(functions)} functions.")

        # add the stablized types
        make_stable_library(self)

    def init(self):
        """Construct memory"""
        self.pd_view_type = PlayDateView.determine_view_type(self.raw)
        self.pd_mem_size = self.raw.end - self.raw.start

        # get root of SDK
        if not self.get_sdk_root():
            log_error("Playdate SDK path required.")
            return False

        # pause all analysis before we add all the symbols and segments
        self.set_analysis_hold(True)

        # create the proper code and data segments
        # binary ninja is AWFUL otherwise
        self.create_segments()
        self.create_sections()

        # create types we know about a la SDK
        self.add_core_pd_types()

        # now that we have specified data / code segments we can
        # "safely" yolo define things, so do it
        self.add_symbols()

        # optionally perform yolo magic, for the most part these are pretty good
        choice = get_choice_input(
            "Yolo type data tables? (see pd-ninja/pd_magic.py)", "yolo?", ["y", "n"])
        if choice is None or choice == 1:
            log_info("not yolo tagging")
        else:
            log_info("yolo tagging some data")
            make_yolo_library()

        self.set_analysis_hold(False)
        return True

    @staticmethod
    def contains_user_tokens(bv: BinaryView) -> bool:
        """Checks if the current binary view contains the necessary user
        tokens, disgusting but it works, cpu go brrrrrrrrrrrrr.
        """
        size = bv.end - bv.start

        # user data generally starts after this far
        search_start = PLAYDATE_USER_DATA_SEARCH_START

        # we cheat a bit here to reduce the search space, though
        # it isn't that big to begin with. if its bigger than a kernel
        # + user dump
        if size > PLAYDATE_KERNEL_SIZE + PLAYDATE_ROUGH_USER_SIZE:
            search_start += PLAYDATE_KERNEL_SIZE

        data = bv.read(search_start, bv.end - search_start)

        # if all the token are found, this is a user section
        for token in USER_TOKEN_LIST:
            if token not in data:
                return False

        return True

    @staticmethod
    def contains_kernel_tokens(bv: BinaryView) -> bool:
        """Checks if the current binary view contains the necessary kernel
        tokens
        """

        # the kernel space is always first and will always be the first
        # 0x50000 bytes, though are tokens should be in the first few kb
        data = bv.read(0, PLAYDATE_KERNEL_SIZE)

        for token in KERNEL_TOKEN_LIST:
            if token not in data:
                return False

        return True

    @staticmethod
    def determine_view_type(bv: BinaryView) -> PDViewType:
        """Figures out what type of dump we are dealing with. The likely
        candidates are user dump or a full dump.
        """
        # we only load from a binary blob, which has 0 on inital view
        if len(bv.segments) > 0:
            return PDViewType.INVALID

        view_type = PDViewType.INVALID
        size = bv.end - bv.start

        # check if the segment is large enough to contain a full dump
        if size > PLAYDATE_USER_SIZE and size <= PLAYDATE_MEM_SIZE:
            # if the segment is large enough for a full dump, check if the
            # tokens are present
            if PlayDateView.contains_kernel_tokens(bv) and PlayDateView.contains_user_tokens(bv):
                view_type = PDViewType.FULL

        else:
            # now we check if this is a user or a kernel dump since its not
            # big enough to be a full dump, note that a kernel dump is
            # smaller than a user mode dump.
            if size > PLAYDATE_KERNEL_SIZE and size <= PLAYDATE_USER_SIZE:
                if PlayDateView.contains_user_tokens(bv):
                    view_type = PDViewType.USER

            else:
                # not big enough to be a user dump, check if it contains
                # the kernel data tokens
                if PlayDateView.contains_kernel_tokens(bv):
                    view_type = PDViewType.KERNEL

        return view_type

    @classmethod
    def is_valid_for_data(cls, data: BinaryView):
        """checks that the data is correct, because this is from a memory
        dump that can be either a user-mode or a kernel-mode dump.
        this is a bit jank, but we do the best with what we've got.
        """
        # get size to see if this is full dump, or just one half
        # (user or kernel)
        view_type = PlayDateView.determine_view_type(data)
        if view_type == PDViewType.INVALID:
            return False

        # we've now determined that this is a valid playdate view
        return True
