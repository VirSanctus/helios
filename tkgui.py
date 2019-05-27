from tkinter import *
from tkinter.filedialog import askopenfilename
from vtlogic import VirusTotalApi


class Window(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master = master
        self.init_window()
        self.vt = VirusTotalApi()

    def init_window(self):
        self.master.title("GUI")
        self.pack(fill=BOTH, expand=1)

        menu = Menu(self.master)
        self.master.config(menu=menu)
        file = Menu(menu)
        file.add_command(label="Exit", command=self.client_exit)
        menu.add_cascade(label="File", menu=file)

        select_button = Button(self, text="Select file", command=self.file_select)
        select_button.pack(side=LEFT)

        selected_file = Text()

    @staticmethod
    def file_select():
        filename = askopenfilename()
        return filename

    @staticmethod
    def client_exit():
        exit()
