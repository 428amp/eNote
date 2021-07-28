import tkinter as tk
from tkinter import scrolledtext, filedialog, simpledialog
from nacl import secret, pwhash, utils
import os
import sys
import random

class mainWindow():
  def _genKey(self, password):
    #takes password as bytes
    kdf = pwhash.argon2i.kdf
    salt = b'0123456789012345' #static salt
    # ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
    ops = pwhash.argon2i.OPSLIMIT_MIN #min ops for faster kdf for convenience
    mem = pwhash.argon2i.MEMLIMIT_SENSITIVE

    key = pwhash.argon2i.kdf(
      secret.SecretBox.KEY_SIZE,
      password,
      salt,
      opslimit=ops,
      memlimit=mem,
      )
    return key

  def _encrypt(self, body, password):
    key = self._genKey(password.encode("utf-8"))
    box = secret.SecretBox(key)
    return box.encrypt(body)

  def _decrypt(self, encrypted, password):
    key = self._genKey(password.encode("utf-8"))
    box = secret.SecretBox(key)
    return box.decrypt(encrypted)

  def _freshFile(self, path, password, title):
    """
    helper function used when file becomes "fresh" after save, open, or new
    """
    self.path = path
    self.password = password
    self.root.title(title)
    self.isModified = False  
    self.fileMenu.entryconfigure("Save", state="disabled")
    self.text.edit_reset() #clear undo stack
    if self.autoHighlight:
    self._format()

  def _new(self, event=None):
    if self.isModified:
      saveOrNot = self._saveUnsaved()
      if saveOrNot is None:
        return
      elif saveOrNot is True:
        self._save()
        if self.isModified:
          return
    if self.text.get("1.0", "end-1c") != "":
      self.isNewFile = True #priming of isNewFile only done when text is not already empty
      self.text.delete("1.0", tk.END)
    self._freshFile(None, None, "Untitled")

  def _open(self, event=None, path=None):
    if self.isModified:
      saveOrNot = self._saveUnsaved()
      if saveOrNot is None:
        return
      elif saveOrNot is True:
        self._save()
        if self.isModified:
          return
    if not path:
      path = tk.filedialog.askopenfilename(filetypes=[("eText Documents", ".etxt"), ("All files", ".*")])
      #if askopenfilename dialog is canceled (no file selected), break early
      if not path:
        return "break"
    else:
      self.root.lower() #root has to be lowered if opening file from commandline arg

    with open(path, "rb") as f:
      bodyRaw = f.read()
    body = None
    dialog = "password:"
    attempts = 0
    self.text.configure(state="disabled")
    while not body:
      try:
        password = tk.simpledialog.askstring(dialog, self.PADDINGPROMPT, show="●")
        if not password:
          self.text.configure(state="normal")
          self.text.focus_force()
          return "break"
        body = self._decrypt(bodyRaw, password)
      except Exception as e:
        dialog = "password - failed verification"
        attempts += 1
    self.text.configure(state="normal")
    
    self.text.delete("1.0", tk.END)
    self.text.insert("end-1c", body.decode("utf-8"))
    self._freshFile(path, password, path)
    self.text.mark_set("insert", "0.1") #reset cursor to start of file
    self.isNewFile = True
    self.text.focus_force()
    return "break" 
  
  def _save(self, event=None):
    def saveAs():
      """
      save current contents of editor to a newly specified path
      """
      path = tk.filedialog.asksaveasfilename(defaultextension=".etxt", filetypes=[("eText Document", ".etxt")])
      print(path)
      if not path:
        return
      #double ask pwd and puke if they dont match
      password = tk.simpledialog.askstring("choose a password:", self.PADDINGPROMPT, show="●")
      if not password:
        return
      passwordConfirm = None
      dialog = "confirm your password:"
      while password != passwordConfirm:
        passwordConfirm = tk.simpledialog.askstring(dialog, self.PADDINGPROMPT, show="●")
        if not passwordConfirm:
          return
        dialog = "passwords do not match. confirm again:"
      self.password = password
      save(path)
    def save(path):
      """
      save current contents of editor to a given path
      """
      body = self.text.get("1.0", "end-1c").encode("utf-8")
      self.text.configure(state="disabled")
      e = self._encrypt(body, self.password)
      self.text.configure(state="normal")
      with open(path, "wb") as f:
        f.write(e)
      self._freshFile(path, self.password, path)
  
    #skip the save if no changes
    if not self.isModified:
      return "break"
    #new file
    if self.path is None:
      saveAs()
    else:
      save(self.path)
    self.text.focus_force()
    return "break"
  
  def _find(self, event=None):
    query = tk.simpledialog.askstring("Find", "string:")
    if not query:
      self.text.focus_force()
      return
    i = "1.0"
    self.text.tag_remove("sel", "1.0", tk.END)
    while True:
      i = self.text.search(query, i, nocase=1, stopindex=tk.END)
      if not i:
        break
      matchEnd = F"{i}+{len(query)}c"
      self.text.tag_add("sel", i, matchEnd)
      i = matchEnd
    self.text.focus_force()
    return "break"

  def _exit(self, event=None):
    if self.isModified:
      saveOrNot = self._saveUnsaved()
      if saveOrNot is None:
        return
      elif saveOrNot is True:
        self._save()
        if self.isModified: #check if self._save() was prematurely canceled since this can't be done through a return value
          return
    self.root.destroy()

  def _saveUnsaved(self):
    """
    prompts the user to choose whether to save unsaved changes.
    """
    fileName = "Untitled"
    if self.path:
      fileName = self.path
    message = F"Do you want to save changes to {fileName}?"
    saveOrNot = tk.messagebox.askyesnocancel(message=message)
    return saveOrNot

  #custom dialog for pass gen
  class passwordConfigDialog(tk.simpledialog.Dialog):    
    def body(self, master):
      self.title("Config New Pass")
      self.minLength, self.maxLength = tk.StringVar(), tk.StringVar()
      tk.Label(master, text="min Length:").grid(sticky="w")
      tk.Entry(master, textvariable=self.minLength).grid(sticky="w", padx=(0, 25))
      self.minLength.set(15)
      tk.Label(master, text="max Length:").grid(sticky="w")
      tk.Entry(master, textvariable=self.maxLength).grid(sticky="w", padx=(0, 25))
      self.maxLength.set(20)
      self.OK = False
      self.Settings = [tk.IntVar() for i in range(4)]
      [setting.set(1) for setting in self.Settings]
      tk.Checkbutton(master, text="Uppercase Letters", variable=self.Settings[0]).grid(sticky="w")
      tk.Checkbutton(master, text="Lowercase Letters", variable=self.Settings[1]).grid(sticky="w")
      tk.Checkbutton(master, text="Digits", variable=self.Settings[2]).grid(sticky="w")
      tk.Checkbutton(master, text="Special Characters", variable=self.Settings[3]).grid(sticky="w")
      
      return master
    
    def apply(self):
      self.OK = True

  def _genNewPassAtCursor(self, event=None):
    #config until valid config selected
    attempts = 0
    while True:
      if attempts > 0:
        message = "Invalid config. A valid config selects at least one type of character and has a max length > positive min length."
        badConfigPopup = tk.messagebox.askokcancel(message=message)
        if not badConfigPopup:
          self.text.focus_force()
          return
      passwordConfig = self.passwordConfigDialog(self.root)
      attempts += 1
      if not passwordConfig.OK:
        self.text.focus_force()
        return
      #must have minLength>0, maxlength>=minLength, at least one of upper,lower,digit,special selected
      minLength = passwordConfig.minLength.get()
      maxLength = passwordConfig.maxLength.get()
      if (not minLength.isdigit()) or (not maxLength.isdigit()):
        continue
      minLength, maxLength = int(minLength), int(maxLength)
      if minLength < 1:
        continue
      if minLength > maxLength:
        continue
      hasSettingsSelected = False
      for setting in passwordConfig.Settings:
        if setting.get():
          hasSettingsSelected = True
          break
      else:
        continue
      break

    #double weight on letters/digits vs symbols
    characters = [
      [chr(ord("A")+i) for i in range(26)]*2,
      [chr(ord("a")+i) for i in range(26)]*2,
      [str(i) for i in range(10)]*2,
      [chr(ord(".")-i) for i in range(10)],
    ]
    characterPool = []
    i = 0
    for setting in passwordConfig.Settings:
      if setting.get():
        characterPool += characters[i]
      i += 1
   
    passLength = random.randrange(int(minLength), int(maxLength)+1)
    password = ""
    for i in range(passLength):
      password += random.choice(characterPool)
    password += "\n"
    currentCursorPos = self.text.index(tk.INSERT)
    self.text.insert(currentCursorPos, password)
    self.text.focus_force()

  def _format(self, event=None):
    """
    format the text for readability
    """
    self._unformat()

    lines = self.text.get("1.0", "end-1c").splitlines()
    inBlock = False
    for i in range(len(lines)):
      line = lines[i]
      if inBlock:
        if line == "":
          inBlock = False
        elif i == blockStart + 1: #designated password line
          self.text.tag_add("passwd", F"{i+1}.0", F"{i+1}.end")
      else:
        if line[:1] == " ":
          self.text.tag_add("login", F"{i+1}.0", F"{i+1}.end")
          inBlock = True
          blockStart = i
        elif line[:2] == "--" and line[-2:] == "--":
          self.text.tag_add("site", F"{i+1}.0", F"{i+1}.end")
    return "break"

  def _unformat(self, event=None):
    self.text.tag_remove("site", "1.0", tk.END)
    self.text.tag_remove("login", "1.0", tk.END)
    self.text.tag_remove("passwd", "1.0", tk.END)

  def _toggleHighlights(self, event=None):
    if self.autoHighlight:
      self._unformat()
    else:
      self._format()
    self.autoHighlight = not self.autoHighlight

  def _modified(self, event=None):
    if self.isNewFile > 0:
      self.isNewFile -= 0.5
      self.text.edit_modified(0)
      return
    if not self.isModified:
      self.root.title("*"+self.root.title())
      self.fileMenu.entryconfigure("Save", state="normal")
    if self.autoHighlight:
      self._format()
    self.isModified = True
    self.text.edit_modified(0)

  def __init__(self, path=None):
    self.root = tk.Tk()
    self.root.geometry("640x640")
    self.root.title("Untitled")

    #init state and constants
    self.PADDINGPROMPT = " "*85
    self.password = None
    self.path = None
    self.isModified = False
    self.isNewFile = False #unusual flag related to <<Modified>> trigger pattern

    #init text widget
    self.text = tk.scrolledtext.ScrolledText(
      self.root, 
      undo=True, 
      font=("Lucida Console", 10),
      )
    self.text.pack(expand=True, fill="both")
    self.text.focus_force()

    #formatting tags
    font = self.text.cget("font")
    self.text.tag_configure("site", font=font+" bold")
    self.text.tag_configure("login", foreground="green")
    self.text.tag_configure("passwd", foreground="blue")
    self.text.tag_lower("site")
    self.text.tag_lower("login")
    self.text.tag_lower("passwd")

    #keybinds
    self.text.bind('<Control-n>', self._new)
    self.text.bind('<Control-o>', self._open)
    self.text.bind('<Control-s>', self._save)
    self.text.bind('<Control-f>', self._find)
    self.text.bind('<Control-p>', self._genNewPassAtCursor)
    self.text.bind('<<Modified>>', self._modified)

    #init dropdown menus
    self.menu = tk.Menu(self.root)
    
    self.fileMenu = tk.Menu(self.menu, tearoff=False)
    self.fileMenu.add_command(label="New", accelerator="Ctrl+N", command=self._new)
    self.fileMenu.add_command(label="Open...", accelerator="Ctrl+O", command=self._open)
    self.fileMenu.add_command(label="Save", accelerator="Ctrl+S", command=self._save, state="disabled")
    self.fileMenu.add_separator()
    self.fileMenu.add_command(label="Exit", command=self._exit)
    self.menu.add_cascade(label="File", menu=self.fileMenu)

    self.editMenu = tk.Menu(self.menu, tearoff=False)
    self.editMenu.add_command(label="New Password", accelerator="Ctrl+P", command=self._genNewPassAtCursor)
    self.editMenu.add_command(label="Find...", accelerator="Ctrl+F", command=self._find)
    self.menu.add_cascade(label="Edit", menu=self.editMenu)

    self.autoHighlight = True
    self.viewMenu = tk.Menu(self.menu, tearoff=False)
    self.checkState = tk.IntVar(value=1)
    self.viewMenu.add_checkbutton(label="Text Highlighting", command=self._toggleHighlights, variable=self.checkState)
    self.menu.add_cascade(label="View", menu=self.viewMenu)
    
    self.root.config(menu=self.menu)
    self.root.protocol('WM_DELETE_WINDOW', self._exit)


    if path:
      self._open(path=path)
    self.root.mainloop()

def main(argv):
  if len(argv) > 1:
    if os.path.isfile(argv[1]):
      mainWindow(argv[1])      
  else:
    mainWindow()

if __name__=='__main__':
  main(sys.argv)
