



# **XrefXpert** 🛠️  
**An advanced cross-reference navigation tool for IDA Pro.**  

## **Overview**  
XrefXpert is a powerful IDA Pro plugin that enhances cross-reference (xref) navigation by providing a **dockable window** displaying all references to a function. It allows quick navigation between xrefs and **auto-syncs** with the pseudocode window for efficient reverse engineering.  

✅ **Instantly list cross-references (xrefs) to a function**  
✅ **Click an xref to open it in the pseudocode window**  
✅ **Use hotkeys (`Shift+X`) to jump between xrefs**  
✅ **Auto-scrolls and highlights the current xref**  
✅ **Docked to the right of the pseudocode window for quick access**  

<img width="985" alt="image" src="https://github.com/user-attachments/assets/f3d00ca7-3f23-4f93-842e-1a5a8870fa1f" />



Filter Down!

<img width="547" alt="image" src="https://github.com/user-attachments/assets/624a80f0-5559-47ee-9495-32a5b33a2141" />

---

## **Installation** 📦  
### **Requirements**  
- **IDA Pro 9.0+**  
- **Python 3.x** (Bundled with IDA Pro)  
- **Hex-Rays Decompiler** (for pseudocode integration)  

### **Steps to Install**  
1. **Download the XrefXpert plugin**  
   - Clone the repository:
     ```sh
     git clone https://github.com/yourusername/XrefXpert.git
     ```
   - Or download the **xrefxpert.py** file manually.

2. **Move the file to IDA's plugin folder**  
   - **Windows:** `C:\Program Files\IDA\plugins\`  
   - **Linux/macOS:** `~/.idapro/plugins/`  

3. **Restart IDA Pro**  
   - The plugin will be available in the **Edit → Plugins** menu.  
   - Or use the **hotkey** `Ctrl+Shift+X` to open it instantly.  

---

## **Usage** 🚀  

### **Opening XrefXpert**  
- **Use the menu:** `Edit → Plugins → XrefXpert`  
- **Press** `Ctrl+Shift+X` to open the XrefXpert window instantly.  

### **Navigating Xrefs**  
1. **Select a function** in IDA.  
2. **XrefXpert automatically lists all xrefs** to that function.  
3. **Click** on an xref to navigate to it in the disassembly or pseudocode view.  
4. **Use `Shift+X`** to jump to the next xref automatically.  

### **Window Docking**  
- **Auto-docks to the right** of the **pseudocode window** for easy analysis.  
- You can **drag and reposition it** in IDA’s UI if needed.  

---

## **Features** 🔥  
| Feature                     | Description |
|-----------------------------|-------------|
| 🔍 **Cross-Reference List**  | Displays all xrefs to the currently selected function. |
| ⚡ **Hotkey Navigation**     | `Shift+X` quickly jumps between xrefs. |
| 🖱️ **Clickable Entries**     | Click an xref to open it in IDA’s pseudocode window. |
| 📜 **Auto-Expanding Columns** | Ensures function signatures are fully visible. |
| 🎨 **Highlighting**          | The currently viewed xref is highlighted in **dark orange**. |
| 🏗️ **Auto-Docking**         | XrefXpert docks **to the right** of the pseudocode window. |

---

## **Supported IDA Pro Features** ✅  
✔ **Works with IDA 9.0+**  
✔ **Supports Hex-Rays pseudocode navigation**  
✔ **Compatible with both 32-bit and 64-bit binaries**  
✔ **Does not modify IDA’s database (safe to use)**  

---

## **Troubleshooting** ⚠️  
### **XrefXpert doesn’t open?**  
- Ensure you are using **IDA Pro 9.0+**.  
- Verify that **xrefxpert.py** is inside the correct **plugins** folder.  
- Restart IDA Pro and check **Edit → Plugins → XrefXpert**.  
- Try running this in IDA’s Python console:  
  ```python
  import idaapi
  idaapi.load_plugin("xrefxpert")
