import customtkinter as ctk

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("App Blocker")
root.geometry("1000x700")

# Левая панель навигации
nav_frame = ctk.CTkFrame(root, width=180, corner_radius=0)
nav_frame.pack(side="left", fill="y")

ctk.CTkLabel(nav_frame, text="Меню", font=("Arial", 20, "bold")).pack(pady=20)
ctk.CTkButton(nav_frame, text="Мониторинг", width=160).pack(pady=10)
ctk.CTkButton(nav_frame, text="Настройки", width=160).pack(pady=10)
ctk.CTkButton(nav_frame, text="О программе", width=160).pack(pady=10)

# Центральная панель
main_frame = ctk.CTkFrame(root, fg_color="transparent")
main_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)

ctk.CTkLabel(main_frame, text="App Blocker", font=("Arial", 26, "bold")).pack(pady=10)
ctk.CTkButton(main_frame, text="🚀 Начать блокировку", width=300, height=50).pack(pady=30)

# Правая панель — логи
log_frame = ctk.CTkFrame(root, width=300)
log_frame.pack(side="right", fill="y")

ctk.CTkLabel(log_frame, text="Логи", font=("Arial", 20, "bold")).pack(pady=20)
log_text = ctk.CTkTextbox(log_frame, width=280, height=500)
log_text.pack(padx=10, pady=10)
log_text.insert("end", "🛡 Готов к блокировке...")

root.mainloop()
