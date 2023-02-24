#!/usr/bin/env python3
"""Loads a custom BinaryView for the Playdate Console
"""
from enum import Enum

from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView, SectionSemantics, SegmentFlag
from binaryninja.log import log_info

# import necessary magic things to look for
from .pd_magic import KERNEL_TOKEN_LIST
from .pd_magic import PLAYDATE_KERNEL_START
from .pd_magic import PLAYDATE_RAM_START
from .pd_magic import PLAYDATE_RAM_SIZE
from .pd_magic import IVT_LEN
from .pd_magic import PLAYDATE_MEM_START
from .pd_magic import PLAYDATE_USER_SIZE
from .pd_magic import PLAYDATE_USER_END
from .pd_magic import PLAYDATE_USER_START
from .pd_magic import STM32F7_IVT_NAMES
from .pd_magic import STM32F7_SRAM_REGIONS
from .pd_magic import PLAYDATE_KERNEL_SIZE
from .pd_magic import PLAYDATE_MEM_SIZE
from .pd_magic import PLAYDATE_ROUGH_USER_SIZE
from .pd_magic import USER_TOKEN_LIST
from .pd_magic import PLAYDATE_USER_DATA_SEARCH_START
from .pd_magic import PLAYDATE_FULL_DUMP_ENTRY_12_3


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

    def add_entry(self):
        thumb_addr_mask = 0xFFFFFFFE

        # set entry
        if self.pd_view_type in [PDViewType.FULL, PDViewType.KERNEL]:
            entry_symbol = self.get_symbol_by_raw_name(STM32F7_IVT_NAMES[1])
            # fall back to known default
            if not entry_symbol:
                self.add_entry_point(PLAYDATE_FULL_DUMP_ENTRY_12_3)
            else:
                self.add_entry_point(entry_symbol.address & thumb_addr_mask)
        else:
            self.add_entry_point(PLAYDATE_USER_START)

    def perform_get_entry_point(self) -> int:
        if self.pd_view_type in [PDViewType.FULL, PDViewType.KERNEL]:
            thumb_addr_mask = 0xFFFFFFFE
            entry_symbol = self.get_symbol_by_raw_name(STM32F7_IVT_NAMES[1])
            # fall back to known default
            if not entry_symbol:
                return PLAYDATE_FULL_DUMP_ENTRY_12_3
            return entry_symbol.address & thumb_addr_mask
        else:
            # user
            return PLAYDATE_USER_START

    def init(self):
        """Construct memory"""
        self.pd_view_type = PlayDateView.determine_view_type(self.raw)
        self.pd_mem_size = self.raw.end - self.raw.start

        # pause all analysis before we add all the symbols and segments
        self.set_analysis_hold(True)

        # create the proper code and data segments
        # binary ninja is AWFUL otherwise
        self.create_segments()
        self.create_sections()

        self.add_entry()

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
