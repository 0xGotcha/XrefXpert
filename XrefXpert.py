import idaapi
import idautils
import idc
import ida_hexrays
import ida_kernwin
from PyQt5 import QtWidgets, QtCore, QtGui  # Fixed QColor import

class XrefViewer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.table = None
        self.xrefs = []
        self.xref_index = -1
        self.current_func = None

    def Show(self):
        return super().Show("Xref Viewer", options=ida_kernwin.PluginForm.WOPN_PERSIST)

    def refresh_xrefs(self):
        """ Refresh the xref list when a function is selected. """
        if not self.table:
            return  # Prevent errors if UI is closing

        self.xrefs.clear()
        self.table.setRowCount(0)

        self.current_func = ida_kernwin.get_screen_ea()
        func = idaapi.get_func(self.current_func)

        if not func:
            ida_kernwin.msg("[XrefViewer] No function found at current address.\n")
            return

        self.xrefs = list(idautils.CodeRefsTo(func.start_ea, False))
        if not self.xrefs:
            ida_kernwin.msg("[XrefViewer] No xrefs found for this function.\n")
            return

        for xref in self.xrefs:
            direction = "Up" if xref > func.start_ea else "Down"
            xref_type = self.get_xref_type(xref)
            function_signature = self.get_function_signature(xref)

            row = self.table.rowCount()
            self.table.insertRow(row)

            # Add data to the table
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(direction))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(xref_type))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(f"0x{xref:X}"))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(function_signature))

        ida_kernwin.msg(f"[XrefViewer] Loaded {len(self.xrefs)} cross-references.\n")

    def get_xref_type(self, xref_addr):
        """ Determine the xref type: Call, Jump, or Data """
        flags = idc.get_full_flags(xref_addr)
        if idc.is_code(flags):
            if idc.print_insn_mnem(xref_addr) in ["call", "jmp"]:
                return "Call" if "call" in idc.print_insn_mnem(xref_addr) else "Jump"
            return "Code"
        elif idc.is_data(flags):
            return "Data"
        return "Unknown"

    def get_function_signature(self, func_ea):
        """ Retrieve the function signature in the format: 
            `ReturnType __fastcall ClassName::FunctionName(Params)`
        """
        func_tinfo = idaapi.tinfo_t()
        if idaapi.get_tinfo(func_tinfo, func_ea):
            function_str = func_tinfo._print()  # Get the function prototype as a string
            return function_str

        return idaapi.get_func_name(func_ea) or "Unknown"

    def OnCreate(self, form):#Create UI elements inside the dockable form
        self.parent = self.FormToPyQtWidget(form)
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Direction", "Type", "Address", "Function"])
        self.table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.table.setSelectionMode(QtWidgets.QTableWidget.SingleSelection)
        self.table.cellClicked.connect(self.on_item_clicked)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)  # Make table read-only

        # Auto-expand the "Function" column
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)  # "Direction" column auto-size
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)  # "Type" column auto-size
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)  # "Address" column auto-size
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)  # "Function" column expands

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.table)
        self.parent.setLayout(layout)

        self.refresh_xrefs()


    def highlight_row(self, index):
        for row in range(self.table.rowCount()):
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    if row == index:
                        item.setForeground(QtGui.QColor("darkorange"))  # Highlight active row text
                    else:
                        item.setForeground(QtGui.QBrush())  # Reset to default text color

    def on_item_clicked(self, row, _):
        """ Handle clicks on xref items """
        addr_item = self.table.item(row, 2)
        if addr_item:
            addr = int(addr_item.text(), 16)
            idaapi.jumpto(addr)
            self.highlight_row(row)
            if ida_hexrays.init_hexrays_plugin():
                ida_hexrays.open_pseudocode(addr, 0)

    def next_xref(self):#Jump to the next xref in the list and scroll to keep it centered
        if not self.xrefs:
            ida_kernwin.msg("[XrefViewer] No cross-references found.\n")
            return

        self.xref_index = (self.xref_index + 1) % len(self.xrefs)
        xref_addr = self.xrefs[self.xref_index]

        idaapi.jumpto(xref_addr)
        self.highlight_row(self.xref_index)

        # Auto-scroll to keep the selected row in the middle
        self.table.scrollToItem(self.table.item(self.xref_index, 0), QtWidgets.QAbstractItemView.PositionAtCenter)

        ida_kernwin.msg(f"[XrefViewer] Jumped to xref at 0x{xref_addr:X}\n")


class XrefViewerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Xref Viewer"
    help = "Displays a list of cross-references for a function"
    wanted_name = "Xref Viewer"
    wanted_hotkey = ""

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
        """ Jump to the next xref """
        if self.xref_view:
            self.xref_view.next_xref()

    def term(self):
        if self.xref_view:
            self.xref_view = None  # Prevent future access after termination

def PLUGIN_ENTRY():
    return XrefViewerPlugin()
