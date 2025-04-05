import sys
import base64
import binascii
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, 
                           QLabel, QTextEdit, QPushButton, QLineEdit, QComboBox, QMessageBox,
                           QGroupBox, QRadioButton, QButtonGroup)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QFont

# Импортируем модули шифрования
from cipher.magenta import encrypt_text as magenta_encrypt_text, decrypt_to_text as magenta_decrypt_to_text, generate_key as magenta_generate_key
from cipher.loki97 import encrypt_text as loki97_encrypt_text, decrypt_to_text as loki97_decrypt_to_text, generate_key as loki97_generate_key
import importlib.util

# Динамически импортируем CAST-256, так как имя файла содержит дефис
spec = importlib.util.spec_from_file_location("cast256", "cipher/cast-256.py")
cast256 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cast256)

class AESCandidateApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES Кандидаты")
        self.setGeometry(100, 100, 900, 600)
        
        # Основной виджет с вкладками
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Создаем вкладки для каждого шифра
        self.setup_magenta_tab()
        self.setup_loki97_tab()
        self.setup_cast256_tab()
        
        # Добавляем меню
        self.setup_menu()

    def setup_menu(self):
        menubar = self.menuBar()
        fileMenu = menubar.addMenu('Файл')
        
        exitAction = QAction('Выход', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.triggered.connect(self.close)
        fileMenu.addAction(exitAction)
        
        helpMenu = menubar.addMenu('Справка')
        aboutAction = QAction('О программе', self)
        aboutAction.triggered.connect(self.show_about)
        helpMenu.addAction(aboutAction)

    def show_about(self):
        QMessageBox.about(self, "О программе", 
                          "Демонстрация шифров-кандидатов AES\n"
                          "Поддерживаемые алгоритмы:\n"
                          "- Magenta\n"
                          "- Loki97\n"
                          "- CAST-256")

    def create_cipher_tab(self, name):
        """Создает вкладку для одного шифра с подвкладками для шифрования и расшифрования"""
        cipher_tab = QTabWidget()
        
        # Вкладка шифрования
        encrypt_tab = QWidget()
        encrypt_layout = QVBoxLayout()
        
        input_group = QGroupBox("Исходный текст")
        input_layout = QVBoxLayout()
        input_text = QTextEdit()
        input_layout.addWidget(input_text)
        input_group.setLayout(input_layout)
        
        key_group = QGroupBox("Ключ")
        key_layout = QVBoxLayout()
        key_options_layout = QHBoxLayout()
        
        use_random_key = QRadioButton("Сгенерировать случайный ключ")
        use_random_key.setChecked(True)
        use_custom_key = QRadioButton("Использовать свой ключ (hex):")
        
        key_options = QButtonGroup()
        key_options.addButton(use_random_key, 1)
        key_options.addButton(use_custom_key, 2)
        
        key_input = QLineEdit()
        key_input.setEnabled(False)
        
        key_options_layout.addWidget(use_random_key)
        key_options_layout.addWidget(use_custom_key)
        key_options_layout.addWidget(key_input)
        
        use_random_key.toggled.connect(lambda checked: key_input.setEnabled(not checked))
        
        key_layout.addLayout(key_options_layout)
        key_group.setLayout(key_layout)
        
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Режим:")
        mode_combo = QComboBox()
        mode_combo.addItem("ECB")  # По умолчанию только ECB
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(mode_combo)
        mode_layout.addStretch()
        
        encrypt_button = QPushButton("Зашифровать")
        
        output_group = QGroupBox("Результат шифрования")
        output_layout = QVBoxLayout()
        output_text = QTextEdit()
        output_text.setReadOnly(True)
        copy_button = QPushButton("Копировать результат")
        output_layout.addWidget(output_text)
        output_layout.addWidget(copy_button)
        output_group.setLayout(output_layout)
        
        key_display_group = QGroupBox("Использованный ключ (hex)")
        key_display_layout = QVBoxLayout()
        key_display = QLineEdit()
        key_display.setReadOnly(True)
        copy_key_button = QPushButton("Копировать ключ")
        key_display_layout.addWidget(key_display)
        key_display_layout.addWidget(copy_key_button)
        key_display_group.setLayout(key_display_layout)
        
        encrypt_layout.addWidget(input_group)
        encrypt_layout.addWidget(key_group)
        encrypt_layout.addLayout(mode_layout)
        encrypt_layout.addWidget(encrypt_button)
        encrypt_layout.addWidget(output_group)
        encrypt_layout.addWidget(key_display_group)
        
        encrypt_tab.setLayout(encrypt_layout)
        
        # Вкладка расшифрования
        decrypt_tab = QWidget()
        decrypt_layout = QVBoxLayout()
        
        encrypted_group = QGroupBox("Зашифрованный текст")
        encrypted_layout = QVBoxLayout()
        encrypted_text = QTextEdit()
        encrypted_layout.addWidget(encrypted_text)
        encrypted_group.setLayout(encrypted_layout)
        
        decrypt_key_group = QGroupBox("Ключ (hex)")
        decrypt_key_layout = QVBoxLayout()
        decrypt_key_input = QLineEdit()
        decrypt_key_layout.addWidget(decrypt_key_input)
        decrypt_key_group.setLayout(decrypt_key_layout)
        
        decrypt_mode_layout = QHBoxLayout()
        decrypt_mode_label = QLabel("Режим:")
        decrypt_mode_combo = QComboBox()
        decrypt_mode_combo.addItem("ECB")
        decrypt_mode_layout.addWidget(decrypt_mode_label)
        decrypt_mode_layout.addWidget(decrypt_mode_combo)
        decrypt_mode_layout.addStretch()
        
        decrypt_button = QPushButton("Расшифровать")
        
        decrypted_group = QGroupBox("Результат расшифрования")
        decrypted_layout = QVBoxLayout()
        decrypted_text = QTextEdit()
        decrypted_text.setReadOnly(True)
        copy_decrypted_button = QPushButton("Копировать результат")
        decrypted_layout.addWidget(decrypted_text)
        decrypted_layout.addWidget(copy_decrypted_button)
        decrypted_group.setLayout(decrypted_layout)
        
        decrypt_layout.addWidget(encrypted_group)
        decrypt_layout.addWidget(decrypt_key_group)
        decrypt_layout.addLayout(decrypt_mode_layout)
        decrypt_layout.addWidget(decrypt_button)
        decrypt_layout.addWidget(decrypted_group)
        
        decrypt_tab.setLayout(decrypt_layout)
        
        # Добавляем подвкладки
        cipher_tab.addTab(encrypt_tab, "Шифрование")
        cipher_tab.addTab(decrypt_tab, "Расшифрование")
        
        # Создаем словарь с элементами для доступа из функций
        elements = {
            'encrypt': {
                'input': input_text,
                'key_options': key_options,
                'key_input': key_input,
                'mode': mode_combo,
                'output': output_text,
                'key_display': key_display,
                'button': encrypt_button,
                'copy_button': copy_button,
                'copy_key_button': copy_key_button
            },
            'decrypt': {
                'input': encrypted_text,
                'key_input': decrypt_key_input,
                'mode': decrypt_mode_combo,
                'output': decrypted_text,
                'button': decrypt_button,
                'copy_button': copy_decrypted_button
            }
        }
        
        return cipher_tab, elements

    def setup_magenta_tab(self):
        """Настраивает вкладку для шифра Magenta"""
        magenta_tab, elements = self.create_cipher_tab("Magenta")
        
        # Настраиваем функциональность кнопок
        def encrypt():
            try:
                text = elements['encrypt']['input'].toPlainText()
                if not text:
                    QMessageBox.warning(self, "Предупреждение", "Введите текст для шифрования")
                    return
                
                if elements['encrypt']['key_options'].checkedId() == 1:  # Случайный ключ
                    key = magenta_generate_key()
                else:  # Пользовательский ключ
                    try:
                        key_hex = elements['encrypt']['key_input'].text().strip()
                        key = bytes.fromhex(key_hex)
                        if len(key) != 16:
                            raise ValueError("Ключ должен быть 16 байт (32 hex символа)")
                    except ValueError as e:
                        QMessageBox.critical(self, "Ошибка", f"Неверный формат ключа: {str(e)}")
                        return
                
                mode = elements['encrypt']['mode'].currentText()
                encrypted = magenta_encrypt_text(text, key, mode)
                elements['encrypt']['output'].setText(encrypted.hex())
                elements['encrypt']['key_display'].setText(key.hex())
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка при шифровании: {str(e)}")
        
        def decrypt():
            try:
                encrypted_hex = elements['decrypt']['input'].toPlainText().strip()
                if not encrypted_hex:
                    QMessageBox.warning(self, "Предупреждение", "Введите зашифрованный текст")
                    return
                
                try:
                    encrypted = bytes.fromhex(encrypted_hex)
                except ValueError:
                    QMessageBox.critical(self, "Ошибка", "Неверный формат зашифрованного текста. Введите hex-строку.")
                    return
                
                try:
                    key_hex = elements['decrypt']['key_input'].text().strip()
                    key = bytes.fromhex(key_hex)
                    if len(key) != 16:
                        raise ValueError("Ключ должен быть 16 байт (32 hex символа)")
                except ValueError as e:
                    QMessageBox.critical(self, "Ошибка", f"Неверный формат ключа: {str(e)}")
                    return
                
                mode = elements['decrypt']['mode'].currentText()
                try:
                    decrypted = magenta_decrypt_to_text(encrypted, key, mode)
                    elements['decrypt']['output'].setText(decrypted)
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка расшифрования", str(e))
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка при расшифровании: {str(e)}")
        
        def copy_encrypted():
            clipboard = QApplication.clipboard()
            clipboard.setText(elements['encrypt']['output'].toPlainText())
            QMessageBox.information(self, "Копирование", "Зашифрованный текст скопирован в буфер обмена")
        
        def copy_key():
            clipboard = QApplication.clipboard()
            clipboard.setText(elements['encrypt']['key_display'].text())
            QMessageBox.information(self, "Копирование", "Ключ скопирован в буфер обмена")
        
        def copy_decrypted():
            clipboard = QApplication.clipboard()
            clipboard.setText(elements['decrypt']['output'].toPlainText())
            QMessageBox.information(self, "Копирование", "Расшифрованный текст скопирован в буфер обмена")
        
        # Привязываем функции к кнопкам
        elements['encrypt']['button'].clicked.connect(encrypt)
        elements['encrypt']['copy_button'].clicked.connect(copy_encrypted)
        elements['encrypt']['copy_key_button'].clicked.connect(copy_key)
        elements['decrypt']['button'].clicked.connect(decrypt)
        elements['decrypt']['copy_button'].clicked.connect(copy_decrypted)
        
        # Добавляем вкладку
        self.tabs.addTab(magenta_tab, "Magenta")

    def setup_loki97_tab(self):
        """Настраивает вкладку для шифра Loki97"""
        loki97_tab, elements = self.create_cipher_tab("Loki97")
        
        # Настраиваем функциональность кнопок
        def encrypt():
            try:
                text = elements['encrypt']['input'].toPlainText()
                if not text:
                    QMessageBox.warning(self, "Предупреждение", "Введите текст для шифрования")
                    return
                
                if elements['encrypt']['key_options'].checkedId() == 1:  # Случайный ключ
                    key = loki97_generate_key()
                else:  # Пользовательский ключ
                    try:
                        key_hex = elements['encrypt']['key_input'].text().strip()
                        key = bytes.fromhex(key_hex)
                        if len(key) != 16:
                            raise ValueError("Ключ должен быть 16 байт (32 hex символа)")
                    except ValueError as e:
                        QMessageBox.critical(self, "Ошибка", f"Неверный формат ключа: {str(e)}")
                        return
                
                mode = elements['encrypt']['mode'].currentText()
                encrypted = loki97_encrypt_text(text, key, mode)
                elements['encrypt']['output'].setText(encrypted.hex())
                elements['encrypt']['key_display'].setText(key.hex())
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка при шифровании: {str(e)}")
        
        def decrypt():
            try:
                encrypted_hex = elements['decrypt']['input'].toPlainText().strip()
                if not encrypted_hex:
                    QMessageBox.warning(self, "Предупреждение", "Введите зашифрованный текст")
                    return
                
                try:
                    encrypted = bytes.fromhex(encrypted_hex)
                except ValueError:
                    QMessageBox.critical(self, "Ошибка", "Неверный формат зашифрованного текста. Введите hex-строку.")
                    return
                
                try:
                    key_hex = elements['decrypt']['key_input'].text().strip()
                    key = bytes.fromhex(key_hex)
                    if len(key) != 16:
                        raise ValueError("Ключ должен быть 16 байт (32 hex символа)")
                except ValueError as e:
                    QMessageBox.critical(self, "Ошибка", f"Неверный формат ключа: {str(e)}")
                    return
                
                mode = elements['decrypt']['mode'].currentText()
                try:
                    decrypted = loki97_decrypt_to_text(encrypted, key, mode)
                    elements['decrypt']['output'].setText(decrypted)
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка расшифрования", str(e))
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка при расшифровании: {str(e)}")
        
        def copy_encrypted():
            clipboard = QApplication.clipboard()
            clipboard.setText(elements['encrypt']['output'].toPlainText())
            QMessageBox.information(self, "Копирование", "Зашифрованный текст скопирован в буфер обмена")
        
        def copy_key():
            clipboard = QApplication.clipboard()
            clipboard.setText(elements['encrypt']['key_display'].text())
            QMessageBox.information(self, "Копирование", "Ключ скопирован в буфер обмена")
        
        def copy_decrypted():
            clipboard = QApplication.clipboard()
            clipboard.setText(elements['decrypt']['output'].toPlainText())
            QMessageBox.information(self, "Копирование", "Расшифрованный текст скопирован в буфер обмена")
        
        # Привязываем функции к кнопкам
        elements['encrypt']['button'].clicked.connect(encrypt)
        elements['encrypt']['copy_button'].clicked.connect(copy_encrypted)
        elements['encrypt']['copy_key_button'].clicked.connect(copy_key)
        elements['decrypt']['button'].clicked.connect(decrypt)
        elements['decrypt']['copy_button'].clicked.connect(copy_decrypted)
        
        # Добавляем вкладку
        self.tabs.addTab(loki97_tab, "Loki97")

    def setup_cast256_tab(self):
        """Настраивает вкладку для шифра CAST-256"""
        cast256_tab, elements = self.create_cipher_tab("CAST-256")
        
        # Настраиваем функциональность кнопок
        def encrypt():
            try:
                text = elements['encrypt']['input'].toPlainText()
                if not text:
                    QMessageBox.warning(self, "Предупреждение", "Введите текст для шифрования")
                    return
                
                if elements['encrypt']['key_options'].checkedId() == 1:  # Случайный ключ
                    key = cast256.generate_key()
                else:  # Пользовательский ключ
                    try:
                        key_hex = elements['encrypt']['key_input'].text().strip()
                        key = bytes.fromhex(key_hex)
                        if len(key) != 32:  # CAST-256 использует 256-битный ключ (32 байта)
                            raise ValueError("Ключ должен быть 32 байта (64 hex символа)")
                    except ValueError as e:
                        QMessageBox.critical(self, "Ошибка", f"Неверный формат ключа: {str(e)}")
                        return
                
                # В CAST-256 нет параметра mode, поэтому мы его игнорируем
                encrypted_b64 = cast256.encrypt_text(text, key)
                elements['encrypt']['output'].setText(encrypted_b64)
                elements['encrypt']['key_display'].setText(key.hex())
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка при шифровании: {str(e)}")
        
        def decrypt():
            try:
                encrypted_b64 = elements['decrypt']['input'].toPlainText().strip()
                if not encrypted_b64:
                    QMessageBox.warning(self, "Предупреждение", "Введите зашифрованный текст")
                    return
                
                try:
                    key_hex = elements['decrypt']['key_input'].text().strip()
                    key = bytes.fromhex(key_hex)
                    if len(key) != 32:  # CAST-256 использует 256-битный ключ
                        raise ValueError("Ключ должен быть 32 байта (64 hex символа)")
                except ValueError as e:
                    QMessageBox.critical(self, "Ошибка", f"Неверный формат ключа: {str(e)}")
                    return
                
                try:
                    decrypted = cast256.decrypt_text(encrypted_b64, key)
                    elements['decrypt']['output'].setText(decrypted)
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка расшифрования", str(e))
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка при расшифровании: {str(e)}")
        
        def copy_encrypted():
            clipboard = QApplication.clipboard()
            clipboard.setText(elements['encrypt']['output'].toPlainText())
            QMessageBox.information(self, "Копирование", "Зашифрованный текст скопирован в буфер обмена")
        
        def copy_key():
            clipboard = QApplication.clipboard()
            clipboard.setText(elements['encrypt']['key_display'].text())
            QMessageBox.information(self, "Копирование", "Ключ скопирован в буфер обмена")
        
        def copy_decrypted():
            clipboard = QApplication.clipboard()
            clipboard.setText(elements['decrypt']['output'].toPlainText())
            QMessageBox.information(self, "Копирование", "Расшифрованный текст скопирован в буфер обмена")
        
        # Так как CAST-256 выводит в base64, скрываем выбор режима
        elements['encrypt']['mode'].setVisible(False)
        elements['encrypt']['mode'].parentWidget().setVisible(False)
        elements['decrypt']['mode'].setVisible(False)
        elements['decrypt']['mode'].parentWidget().setVisible(False)
        
        # Привязываем функции к кнопкам
        elements['encrypt']['button'].clicked.connect(encrypt)
        elements['encrypt']['copy_button'].clicked.connect(copy_encrypted)
        elements['encrypt']['copy_key_button'].clicked.connect(copy_key)
        elements['decrypt']['button'].clicked.connect(decrypt)
        elements['decrypt']['copy_button'].clicked.connect(copy_decrypted)
        
        # Добавляем вкладку
        self.tabs.addTab(cast256_tab, "CAST-256")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Устанавливаем стиль
    app.setStyle("Fusion")
    
    window = AESCandidateApp()
    window.show()
    
    sys.exit(app.exec())
