import glob
import json
import tarfile
from tkinter import *
from tkinter import filedialog as fd
from tkinter import ttk
from tkinter.font import Font
import requests
import audit
import re

main = Tk()
main.resizable(False, False)
app_font = Font(family="Courier New", size=12)
s = ttk.Style()
s.configure('TFrame', background='#123456')
main.title("Security Benchmarking Tool")
main.geometry("950x550")
frame = ttk.Frame(main, width=950, height=550, style='TFrame')
frame.grid(column=0, row=0)


index = 0
arr = []
matching = []

vars = StringVar()
tofile = []
structure = []

def download_url(url, save_path, chunk_size=1024):
    r = requests.get(url, stream=True)
    with open(save_path, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=chunk_size):
            fd.write(chunk)

def extract_file():
    url = "https://www.tenable.com/downloads/api/v1/public/pages/download-all-compliance-audit-files/downloads/7472/download?i_agree_to_tenable_license_agreement=true"
    download_url(url, "audits.tar.gz")
    tf = tarfile.open("audits.tar.gz")
    tf.extractall()
    print(glob.glob("portal_audits/*"))

def import_audit():
    global arr
    file_name = fd.askopenfilename(initialdir="../portal_audits")
    if file_name:
        arr = []
    global structure
    structure = audit.main(file_name)
    for element in structure:
        for key in element:
            str = ''
            for char in element[key]:
                if char != '"' and char != "'":
                    str += char
            isspacefirst = True
            str2 = ''
            for char in str:
                if char == ' ' and isspacefirst:
                    continue
                else:
                    str2 += char
                    isspacefirst = False
            element[key] = str2

    global matching
    matching = structure
    if len(structure) == 0:
        f = open(file_name, 'r')
        structure = json.loads(f.read())
        f.close()
    for struct in structure:
        if 'description' in struct:
            arr.append(struct['description'])
        else:
            arr.append('Error in selecting')
    vars.set(arr)


lstbox = Listbox(frame, bg="#000000", font=app_font, fg="white", listvariable=vars, selectmode=MULTIPLE, width=75, selectbackground='#519487',height=20, highlightthickness=3)
lstbox.grid(row=0, column=0, columnspan=3, padx=100, pady=100)

def save_config():
    lstbox.select_set(0, END)
    for struct in structure:
        lstbox.insert(END, struct)

    file_name = fd.asksaveasfilename(filetypes=(("AUDIT FILES", ".audit"), ("All files", ".")))
    file_name += '.audit'
    file = open(file_name, 'w')
    selection = lstbox.curselection()
    for i in selection:
        tofile.append(matching[i])
    json.dump(tofile, file)
    file.close()

btn_font = Font(family="Courier New", size=10)
save_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Save", width=8, height=1, command=save_config).place(relx=0.01, rely=0.01)
import_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Import", width=8, height=1,command=import_audit).place(relx=0.01, rely=0.065)
download_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Download", width=8, height=1,command=extract_file).place(relx=0.01, rely=0.12)
exit_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Exit", width=8, height=1,command=main.quit).place(relx=0.01, rely=0.175)


main.mainloop()