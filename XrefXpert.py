import idaapi
import idautils
import idc
import ida_hexrays
import ida_kernwin
from PyQt5 import QtWidgets, QtCore, QtGui

class XrefViewer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.table = None
        self.xrefs = []
        self.current_xrefs = []  # Holds current sorted order
        self.xref_index = -1
        self.current_func = None

    def Show(self):
        return super().Show("Xref Viewer", options=ida_kernwin.PluginForm.WOPN_PERSIST)

    def refresh_xrefs(self):
        if not self.table:
            return

        self.xrefs.clear()
        self.table.setRowCount(0)

        self.current_func = ida_kernwin.get_screen_ea()
        func = idaapi.get_func(self.current_func)

        if not func:
            ida_kernwin.msg("[XrefViewer] No function found at current address.\n")
            return

        refs = list(idautils.CodeRefsTo(func.start_ea, False))
        if not refs:
            ida_kernwin.msg("[XrefViewer] No xrefs found for this function.\n")
            return

        self.xrefs = []
        for xref in refs:
            direction = "Up" if xref > func.start_ea else "Down"
            xref_type = self.get_xref_type(xref)
            function_signature = self.get_function_signature(xref)
            param_count = self.get_param_count(xref)

            self.xrefs.append((direction, xref_type, xref, function_signature, param_count))

        self.populate_table()

    def populate_table(self):
        self.table.setRowCount(0)
        for data in self.xrefs:
            direction, xref_type, xref, function_signature, param_count = data
            row = self.table.rowCount()
            self.table.insertRow(row)

            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(direction))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(xref_type))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(f"0x{xref:X}"))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(function_signature))
            self.table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(param_count)))

        self.current_xrefs = self.xrefs.copy()
        ida_kernwin.msg(f"[XrefViewer] Loaded {len(self.xrefs)} cross-references.\n")

    def get_xref_type(self, xref_addr):
        flags = idc.get_full_flags(xref_addr)
        if idc.is_code(flags):
            mnem = idc.print_insn_mnem(xref_addr)
            return "Call" if mnem == "call" else "Jump" if mnem == "jmp" else "Code"
        elif idc.is_data(flags):
            return "Data"
        return "Unknown"

    def get_function_signature(self, func_ea):
        func_tinfo = idaapi.tinfo_t()
        if idaapi.get_tinfo(func_tinfo, func_ea):
            return func_tinfo._print()
        return idaapi.get_func_name(func_ea) or "Unknown"

    def get_param_count(self, func_ea):
        func = idaapi.get_func(func_ea)
        if not func:
            return 0
        decompiled = idaapi.decompile(func.start_ea) if ida_hexrays.init_hexrays_plugin() else None
        return decompiled.type.get_nargs() if decompiled else 0

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Direction", "Type", "Address", "Function", "Params"])
        self.table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.table.setSelectionMode(QtWidgets.QTableWidget.SingleSelection)
        self.table.cellClicked.connect(self.on_item_clicked)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().sectionClicked.connect(self.remember_sorting)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.table)
        self.parent.setLayout(layout)

        self.refresh_xrefs()

    def remember_sorting(self):
        """Remembers the sorted order so that next_xref follows it."""
        self.current_xrefs = [
            (
                self.table.item(row, 0).text(),
                self.table.item(row, 1).text(),
                int(self.table.item(row, 2).text(), 16),
                self.table.item(row, 3).text(),
                int(self.table.item(row, 4).text()),
            )
            for row in range(self.table.rowCount())
        ]

    def highlight_row(self, index):
        """Highlights the selected row and resets others."""
        for row in range(self.table.rowCount()):
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    if row == index:
                        item.setForeground(QtGui.QColor("darkorange"))  # Highlight active row text
                        item.setBackground(QtGui.QBrush(QtGui.QColor(50, 50, 50)))  # Darker background
                    else:
                        item.setForeground(QtGui.QBrush())  # Reset text color
                        item.setBackground(QtGui.QBrush())  # Reset background

    def on_item_clicked(self, row, _):
        """Handles row clicks to jump to the address and highlight."""
        addr = int(self.table.item(row, 2).text(), 16)
        idaapi.jumpto(addr)
        self.highlight_row(row)
        ida_hexrays.open_pseudocode(addr, 0)
        self.xref_index = row  # Update xref index to allow proper 'next' navigation

    def next_xref(self):
        """Moves to the next xref in the sorted list."""
        if not self.current_xrefs:
            ida_kernwin.msg("[XrefViewer] No cross-references found.\n")
            return

        self.xref_index = (self.xref_index + 1) % len(self.current_xrefs)
        _, _, addr, _, _ = self.current_xrefs[self.xref_index]

        idaapi.jumpto(addr)
        self.highlight_row(self.xref_index)
        self.table.scrollToItem(self.table.item(self.xref_index, 0), QtWidgets.QAbstractItemView.PositionAtCenter)
        ida_kernwin.msg(f"[XrefViewer] Jumped to xref at 0x{addr:X}\n")

class XrefViewerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "XrefXpert"
    help = "Displays a list of cross-references for a function"
    wanted_name = "XrefXpert"

    def __init__(self):
        self.xref_view = None

    def init(self):
        ida_kernwin.add_hotkey("Ctrl+Shift+X", self.show_xref_window)
        ida_kernwin.add_hotkey("Shift+X", self.next_xref)
        return idaapi.PLUGIN_KEEP

    def show_xref_window(self):
        if not self.xref_view:
            self.xref_view = XrefViewer()
        self.xref_view.Show()
        self.xref_view.refresh_xrefs()

    def next_xref(self):
        if self.xref_view:
            self.xref_view.next_xref()

    def term(self):
        if self.xref_view:
            self.xref_view = None  # Prevent future access after termination

def PLUGIN_ENTRY():
    return XrefViewerPlugin()
