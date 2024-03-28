import tkinter as tk

def switch_to_page1():
    page2.pack_forget()
    page1.pack()

def switch_to_page2():
    page1.pack_forget()
    page2.pack()

root = tk.Tk()

menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

page1 = tk.Frame(root)
page2 = tk.Frame(root)

button1 = tk.Button(page1, text="进入次页", command=switch_to_page2)
button1.pack()

button2 = tk.Button(page2, text="返回首页", command=switch_to_page1)
button2.pack()

page1.pack()

root.mainloop()
