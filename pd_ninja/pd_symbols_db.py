#!/usr/bin/env python3
"""Utilities for loadng and applying symbols from symbols.db
"""
from pathlib import Path
from typing import Iterable
from typing import NamedTuple
from argparse import ArgumentParser

from sqlalchemy import func
from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy import Integer
from sqlalchemy import create_engine
from sqlalchemy import ForeignKey
from sqlalchemy import Engine
from sqlalchemy import select
from sqlalchemy import ScalarResult
from sqlalchemy import distinct
from sqlalchemy.orm import Session
from sqlalchemy.orm import declarative_base

Base = declarative_base()
"""
``Base`` will be roughly equivalent to the following:

.. code-block:: sql

    CREATE TABLE functions (name TEXT, low INT);
    CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT);
    CREATE TABLE lines
                    (id INTEGER PRIMARY KEY,
                    low INT,
                    file_id INT,
                    lineno INT,
                    FOREIGN KEY(file_id) REFERENCES files(id)
                    );
    -- CREATE INDEX f_addr_range on functions (low);
    -- CREATE INDEX l_addr_range on lines (low);
"""


class Functions(Base):
    __tablename__ = "functions"

    # because there is no primary key, we compose a candidate key
    # by declaring both of these columns a "primary key" to the ORM
    name = Column(String, primary_key=True)
    low = Column(Integer, primary_key=True)

    def to_symbol_info(self) -> "SymbolInfo":
        return SymbolInfo(self.name, self.low)


class Files(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True)
    path = Column(String)


class Lines(Base):
    __tablename__ = "lines"

    id = Column(Integer, primary_key=True)
    low = Column(Integer)
    file_id = Column(Integer, ForeignKey("files.id"))
    lineno = Column(Integer)


def load_db(path: Path) -> Engine:
    """Returns the sqlalchemy connection from the sqlite db @ path.

    Parameters
    ----------
    path : Path
        path to the sqlite db

    Returns
    -------
    Engine
        engine connection to the sqlite db
    """
    return create_engine(f"sqlite:///{str(path.resolve())}")


class SymbolInfo(NamedTuple):
    name: str
    address: int

    def __str__(self) -> str:
        return f"Symbol{{{self.name}: {hex(self.address)}}}"


class FileInfo(NamedTuple):
    name: str
    functions: Iterable[SymbolInfo]


class SymbolsDB:
    """Simple RO wrapper class over the ``symbols.db``"""

    def __init__(self, path: Path):
        self.engine = load_db(path)
        self.session = Session(self.engine)

    def query(self, stmt: select) -> ScalarResult:
        return self.session.scalars(stmt)

    def get_functions(self, strip_hidden: bool = False) -> Iterable[SymbolInfo]:
        """Get all functions, note that there are probably functions with
        address collisions. Use ``.get_first_functions()`` to avoid this.
        """

        # get all functions and return them
        stmt = select(Functions)
        func_symbols = [f.to_symbol_info() for f in self.query(stmt)]

        if strip_hidden:
            func_symbols = list(filter(
                lambda x: x.name != "hidden", func_symbols))
        return func_symbols

    def get_first_functions(self, strip_hidden: bool = False) -> Iterable[SymbolInfo]:
        """Get all functions, but only return one function per address.
        Performs the following query:

        .. code-block:: SQL

            SELECT * FROM functions
                WHERE low IN
                    (SELECT DISTINCT(low)
                        FROM functions);
        """
        stmt = select(Functions).where(
            Functions.low.in_(select(distinct(Functions.low))))
        func_symbols = [f.to_symbol_info() for f in self.query(stmt)]

        if strip_hidden:
            func_symbols = list(filter(
                lambda x: x.name != "hidden", func_symbols))

        return func_symbols

    def get_duplicate_functions(self, strip_hidden: bool = False) -> Iterable[SymbolInfo]:
        """Get only functions that have address collisions,
        equivalent to the following SQL:

        .. code-block:: SQL

            SELECT * FROM functions
                WHERE low IN 
                    (SELECT low FROM functions
                        GROUP BY low
                            HAVING COUNT(low) > 1);
        """
        duplicate_addr_stmt = select(Functions.low) \
            .group_by(Functions.low) \
            .having(func.count(Functions.low) > 1)
        stmt = select(Functions).where(Functions.low.in_(duplicate_addr_stmt))
        func_symbols = [f.to_symbol_info() for f in self.query(stmt)]

        if strip_hidden:
            func_symbols = list(filter(
                lambda x: x.name != "hidden", func_symbols))
        return func_symbols

    def group_functions_by_file(self, strip_hidden: bool = False) -> FileInfo:
        """Complicated and I'm lazy, not implemented, pretty sure there's
        some information missing too
        """
        raise NotImplementedError("Did not implement the yolo join stuff")


if __name__ == "__main__":
    p = ArgumentParser()
    p.add_argument("input", type=Path,
                   help="path to input symbols.db", default="symbols.db")

    args = p.parse_args()

    s = SymbolsDB(args.input)

    funcs = s.get_first_functions()
    print(funcs)
