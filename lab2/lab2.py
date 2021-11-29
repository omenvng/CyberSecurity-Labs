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
global perv

main = Tk()
main.resizable(False, False)
app_font = Font(family="Courier New", size=7)
s = ttk.Style()
s.configure('TFrame', background='#123456')
main.title("Security Benchmarking Tool")
main.geometry("950x550")
frame = ttk.Frame(main, width=950, height=550, style='TFrame')
frame.grid(column=0, row=0)

prev = []
index = 0
arr = []
matching = []
querry = StringVar()
vars = StringVar()
tofile = []
structure = []

def input_find(term):
    find()

def find():
    global structure
    q = querry.get()
    arr = [st['description'] for st in structure if q.lower() in st['description'].lower()]
    global matching
    matching = [st for st in structure if q in st['description']]
    vars.set(arr)

def on_select(term):
    global prev
    global idx 
    w = term.widget
    actual = w.curselection()

    diff = [item for item in actual if item not in prev]
    if len(diff) > 0:
        idx = [item for item in actual if item not in prev][0]
    prev = w.curselection()

    text.delete(1.0, END)
    str = '\n'
    for key in matching[idx]:
        str += key + ':' + matching[idx][key] + '\n'
    text.insert(END,str)


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

def select_all():
    lstbox.select_set(0, END)
    for st in structure:
        lstbox.insert(END, st)

def deselect_all():
    for st in structure:
        lstbox.selection_clear(0, END)

lstbox = Listbox(frame, bg = "#000000", font = app_font, fg = "white", listvariable = vars, selectmode = MULTIPLE, width = 150, selectbackground = '#519487', height = 34, highlightthickness = 3)
lstbox.grid(row = 0, column = 0, columnspan = 3, padx = 130, pady = 50)
lstbox.bind('<<ListboxSelect>>', on_select)

def save_config():
    file_name = fd.asksaveasfilename(filetypes=(("AUDIT FILES", ".audit"), ("All files", ".")))
    file_name += '.audit'
    file = open(file_name, 'w')
    selection = lstbox.curselection()
    for i in selection:
        tofile.append(matching[i])
    json.dump(tofile, file)
    file.close()

text = Text(frame, bg="#123456", fg="white", font=app_font, width=105, height=45, highlightthickness=3)
btn_font = Font(family="Courier New", size=10)
save_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Save", width=13, height=1, command=save_config).place(relx=0.01, rely=0.01)
import_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Import", width=13, height=1,command=import_audit).place(relx=0.01, rely=0.065)
download_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Download", width=13, height=1,command=extract_file).place(relx=0.01, rely=0.12)
select_all_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Select All", width=13, height=1,command=select_all).place(relx=0.01, rely=0.175)
deselect_all_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Deselect All", width=13, height=1,command=deselect_all).place(relx=0.01, rely=0.229)
exit_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Exit", width=13, height=1,command=main.quit).place(relx=0.01, rely=0.284)
global e
e = Entry(frame, bg="#ff5432", font=btn_font, width=25, textvariable=querry).place(relx=0.2, rely=0.04)
find_btn = Button(frame, bg="#ff5432", fg="white", font=btn_font, text="Find", width=8, height=1,command=find).place(relx=0.41, rely=0.035)
main.bind('<Return>', input_find)
main.mainloop()