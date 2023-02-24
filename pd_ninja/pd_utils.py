#!/usr/bin/env python3
from typing import NamedTuple
from typing import Optional
from pathlib import Path

from binaryninja.log import log_error
from binaryninja.binaryview import Section
from binaryninja.binaryview import BinaryView
from binaryninja.interaction import get_directory_name_input


class PlaydateSDKMetadata(NamedTuple):
    root: Path
    symbols_db: Path
    header_path: Path

def get_sdk_root() -> Optional[PlaydateSDKMetadata]:
    """Gets the path to the SDK root

    Returns
    -------
    PlaydateSDKMetadata
        metadata to differrent paths in the sdk
    """
    pd_path = get_directory_name_input("Path to PlaydateSDK:")

    if not pd_path:
        return None

    p = Path(pd_path)
    if not p.exists():
        log_error("invalid path")
        return None

    if not p.is_dir():
        log_error("not a directory")
        return None

    p = p.resolve().absolute()
    pd_symbols_path = p / "bin" / "symbols.db"
    pd_header_path = p / "C_API" / "pd_api.h"

    if not pd_header_path.exists() or not pd_header_path.is_file():
        log_error(
            f"Could not find file for header at {pd_header_path}")

    if not pd_symbols_path.exists() or not pd_symbols_path.is_file():
        log_error(
            f"Could not find file for header at {pd_symbols_path}")

    m = PlaydateSDKMetadata(p, pd_symbols_path, pd_header_path)
    return m

def addr_valid(bv: BinaryView, address: int) -> bool:
    """Checks if an address is valid for the current binaryview

    Parameters
    ----------
    bv : BinaryView
        bv to check against
    address : int
        address to check

    Returns
    -------
    bool
        if the address is valid
    """
    for r in [(s.start, s.end) for s in bv.segments]:
        if address >= r[0] and address < r[1]:
            return True
    return False

def dest_section(bv: BinaryView, address: int) -> Section:
    """Returns the corresponding section that an address
    is a member of.

    Parameters
    ----------
    bv : BinaryView
        bv to check against
    address : int
        address to check

    Returns
    -------
    Section
        parent section
    
    Raises
    ------
    ValueError if there is no section containing the address
    """
    for sec in bv.sections.values():
        if address >= sec.start and address < sec.end:
            return sec
    raise ValueError(f"No section containing address: {address}")