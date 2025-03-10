import idaapi
import idautils
import idc
import ida_hexrays
import ida_kernwin
import ida_bytes
import ida_ida
from PyQt5 import QtWidgets, QtCore, QtGui

class XrefViewer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.table = None
        self.xrefs = []
        self.filtered_xrefs = []
        self.current_xrefs = []
        self.xref_index = -1
        self.current_func = None
        self.param_filter = None
        self.immediate_filter = None
        self.binary_filter = None

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

        self.apply_filter()

    def apply_filter(self):
        filtered = self.xrefs

        if self.param_filter is not None:
            filtered = [entry for entry in filtered if entry[4] == self.param_filter]

        if self.immediate_filter is not None:
            filtered = [entry for entry in filtered if self.contains_immediate(entry[2], self.immediate_filter)]

        if self.binary_filter is not None:
            filtered = self.search_pattern(self.binary_filter)  # Now properly filtering

        self.filtered_xrefs = filtered
        self.populate_table()


    def contains_immediate(self, func_ea, imm_value):
        func = idaapi.get_func(func_ea)
        if not func:
            return False

        ea = func.start_ea
        while ea < func.end_ea:
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, ea):  # Decode instruction
                for i in range(len(insn.ops)):  # Iterate over operands
                    op = insn.ops[i]

                    # Check immediate values (o_imm)
                    if op.type == idaapi.o_imm:
                        if op.value == imm_value or op.value & 0xFFFFFFFF == imm_value:
                            return True

                    # Check memory operand (o_mem) in case the offset is encoded as an address
                    if op.type == idaapi.o_mem:
                        if op.addr == imm_value or op.addr & 0xFFFFFFFF == imm_value:
                            return True

                    # Check displacement (o_displ) in case offset is encoded inside an address calculation
                    if op.type == idaapi.o_displ:
                        if op.addr == imm_value or op.addr & 0xFFFFFFFF == imm_value:
                            return True

            ea = idaapi.next_head(ea, func.end_ea)

        return False


    def search_pattern(self, pattern):
        if not self.filtered_xrefs:
            return []

        compiled_pattern = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(compiled_pattern, idaapi.get_imagebase(), pattern, 16)

        if err:
            ida_kernwin.msg(f"[XrefViewer] ERROR: Failed to parse pattern '{pattern}': {err}\n")
            return []

        matching_entries = []

        for entry in self.filtered_xrefs:
            _, _, func_ea, _, _ = entry
            func = idaapi.get_func(func_ea)
            if not func:
                continue  # Skip if not inside a function

            min_ea = func.start_ea
            max_ea = func.end_ea

            result = ida_bytes.bin_search3(min_ea, max_ea, compiled_pattern, ida_bytes.BIN_SEARCH_FORWARD)

            while result and result[0] != idaapi.BADADDR and result[0] < max_ea:
                matching_entries.append(entry)
                break  # Stop searching for this function after first match

        return matching_entries




    def populate_table(self):
        self.table.setRowCount(0)
        for data in self.filtered_xrefs:
            direction, xref_type, xref, function_signature, param_count = data
            row = self.table.rowCount()
            self.table.insertRow(row)

            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(direction))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(xref_type))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(f"0x{xref:X}"))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(function_signature))
            self.table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(param_count)))

        self.current_xrefs = self.filtered_xrefs.copy()
        ida_kernwin.msg(f"[XrefViewer] Loaded {len(self.filtered_xrefs)} cross-references.\n")

    def show_context_menu(self, pos):
        """Displays the right-click filter menu."""
        menu = QtWidgets.QMenu(self.table)
        filter_menu = menu.addMenu("Filter")
        
        set_param_filter_action = filter_menu.addAction("Set Parameter Count")
        set_imm_filter_action = filter_menu.addAction("Set Immediate Value Filter")
        set_bin_filter_action = filter_menu.addAction("Set Binary Signature Filter")
        clear_filter_action = filter_menu.addAction("Clear Filters")

        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if action == set_param_filter_action:
            self.set_param_filter()
        elif action == set_imm_filter_action:
            self.set_immediate_filter()
        elif action == set_bin_filter_action:
            self.set_binary_filter()
        elif action == clear_filter_action:
            self.param_filter = None
            self.immediate_filter = None
            self.binary_filter = None
            self.apply_filter()

    def set_param_filter(self):
        """Prompts for parameter count."""
        text, ok = QtWidgets.QInputDialog.getInt(self.parent, "Set Filter", "Show functions with exactly N parameters:")
        if ok:
            self.param_filter = text
            self.apply_filter()

    def set_immediate_filter(self):
        """Prompts for an immediate value filter."""
        text, ok = QtWidgets.QInputDialog.getInt(self.parent, "Set Filter", "Show functions containing this immediate value:")
        if ok:
            self.immediate_filter = text
            self.apply_filter()

    def set_binary_filter(self):
        """Prompts for a binary signature filter."""
        text, ok = QtWidgets.QInputDialog.getText(self.parent, "Set Filter", "Enter binary pattern (e.g. '55 8B EC'):")
        if ok and text.strip():
            self.binary_filter = text.strip()
            self.apply_filter()

    def get_xref_type(self, xref_addr):
            flags = idc.get_full_flags(xref_addr)
            if idc.is_code(flags):
                mnem = idc.print_insn_mnem(xref_addr)
                return "Call" if mnem == "call" else "Jump" if mnem == "jmp" else "Code"
            elif idc.is_data(flags):
                return "Data"
            return "Unknown"

    def get_function_signature(self, func_ea):
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

        # Context menu policy (right-click menu)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

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

    def show_context_menu(self, pos):
        """Creates the right-click menu."""
        menu = QtWidgets.QMenu(self.table)
        filter_menu = menu.addMenu("Filter")
        
        filter_menu.addAction("Set Parameter Count", self.set_param_filter)
        filter_menu.addAction("Set Immediate Value Filter", self.set_immediate_filter)
        filter_menu.addAction("Set Binary Signature Filter", self.set_binary_filter)
        filter_menu.addAction("Clear Filters", self.clear_filters)

        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def clear_filters(self):
        """Clears all filters and refreshes the table."""
        self.param_filter = None
        self.immediate_filter = None
        self.binary_filter = None
        self.apply_filter()

    def highlight_row(self, index):
        """Highlights the selected row and resets others."""
        for row in range(self.table.rowCount()):
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    if row == index:
                        item.setForeground(QtGui.QColor("darkorange"))
                        item.setBackground(QtGui.QBrush(QtGui.QColor(50, 50, 50)))
                    else:
                        item.setForeground(QtGui.QBrush())
                        item.setBackground(QtGui.QBrush())

    def on_item_clicked(self, row, _):
        addr = int(self.table.item(row, 2).text(), 16)
        idaapi.jumpto(addr)
        self.highlight_row(row)
        ida_hexrays.open_pseudocode(addr, 0)
        self.xref_index = row

    def next_xref(self):
        """Moves to the next xref in the filtered and sorted list."""
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
        self.xref_view = None

def PLUGIN_ENTRY():
    return XrefViewerPlugin()
