import streamlit as st
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# -------------------- AES ENCRYPTION --------------------
def encrypt(text, key):
    key = key.encode('utf-8').ljust(16, b'\0')[:16]
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted).decode('utf-8')

def decrypt(encrypted_text, key):
    key = key.encode('utf-8').ljust(16, b'\0')[:16]
    data = base64.b64decode(encrypted_text)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')

# -------------------- DATABASE --------------------
def init_db():
    conn = sqlite3.connect("data_pribadi.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama TEXT,
            nik TEXT,
            alamat TEXT,
            no_hp TEXT
        )
    """)
    conn.commit()
    conn.close()

def simpan_data(nama, nik, alamat, no_hp):
    conn = sqlite3.connect("data_pribadi.db")
    cur = conn.cursor()
    cur.execute("INSERT INTO users (nama, nik, alamat, no_hp) VALUES (?, ?, ?, ?)",
                (nama, nik, alamat, no_hp))
    conn.commit()
    conn.close()

def ambil_semua_data():
    conn = sqlite3.connect("data_pribadi.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")
    data = cur.fetchall()
    conn.close()
    return data

def hapus_data(id):
    conn = sqlite3.connect("data_pribadi.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (id,))
    conn.commit()
    conn.close()

def update_data(id, nama, nik, alamat, no_hp):
    conn = sqlite3.connect("data_pribadi.db")
    cur = conn.cursor()
    cur.execute("""
        UPDATE users SET nama = ?, nik = ?, alamat = ?, no_hp = ? WHERE id = ?
    """, (nama, nik, alamat, no_hp, id))
    conn.commit()
    conn.close()

# -------------------- APLIKASI STREAMLIT --------------------
st.set_page_config(page_title="Aplikasi Keamanan Data Pribadi", layout="centered")
st.title("🔒 Aplikasi Enkripsi Data Pribadi")

init_db()
menu = st.sidebar.radio("Navigasi", ["Enkripsi Data", "Lihat Data", "Dekripsi Data"])

if menu == "Enkripsi Data":
    st.subheader("🧾 Input Data Pribadi")
    nama = st.text_input("Nama Lengkap")
    nik = st.text_input("NIK")
    alamat = st.text_area("Alamat")
    no_hp = st.text_input("Nomor HP")
    kunci = st.text_input("Masukkan Kunci Rahasia", type="password")

    if st.button("🔐 Enkripsi dan Simpan"):
        if all([nama, nik, alamat, no_hp, kunci]):
            e_nama = encrypt(nama, kunci)
            e_nik = encrypt(nik, kunci)
            e_alamat = encrypt(alamat, kunci)
            e_no_hp = encrypt(no_hp, kunci)
            simpan_data(e_nama, e_nik, e_alamat, e_no_hp)
            st.success("✅ Data terenkripsi dan tersimpan!")
        else:
            st.warning("⚠️ Semua field harus diisi!")

elif menu == "Lihat Data":
    st.subheader("📋 Data Pribadi (Terenkripsi) + Edit & Hapus")
    data = ambil_semua_data()
    if data:
        for row in data:
            st.markdown(f"**ID: {row[0]}**")
            st.text(f"Nama: {row[1]}")
            st.text(f"NIK: {row[2]}")
            st.text(f"Alamat: {row[3]}")
            st.text(f"Nomor HP: {row[4]}")

            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button(f"✏️ Edit ID {row[0]}"):
                    st.session_state['edit_id'] = row[0]
            with col2:
                if st.button(f"🗑 Hapus ID {row[0]}"):
                    hapus_data(row[0])
                    st.success(f"✅ Data ID {row[0]} dihapus.")
                    st.rerun()

        if 'edit_id' in st.session_state:
            edit_id = st.session_state['edit_id']
            st.subheader(f"✏️ Edit Data ID {edit_id}")
            kunci_edit = st.text_input("Masukkan Kunci untuk Dekripsi", type="password", key="kunci_edit")
            row = next((r for r in data if r[0] == edit_id), None)
            if row and kunci_edit:
                try:
                    nama = decrypt(row[1], kunci_edit)
                    nik = decrypt(row[2], kunci_edit)
                    alamat = decrypt(row[3], kunci_edit)
                    no_hp = decrypt(row[4], kunci_edit)

                    new_nama = st.text_input("Nama", nama)
                    new_nik = st.text_input("NIK", nik)
                    new_alamat = st.text_area("Alamat", alamat)
                    new_no_hp = st.text_input("No HP", no_hp)

                    if st.button("💾 Simpan Perubahan"):
                        e_nama = encrypt(new_nama, kunci_edit)
                        e_nik = encrypt(new_nik, kunci_edit)
                        e_alamat = encrypt(new_alamat, kunci_edit)
                        e_no_hp = encrypt(new_no_hp, kunci_edit)
                        update_data(edit_id, e_nama, e_nik, e_alamat, e_no_hp)
                        st.success("✅ Data berhasil diperbarui!")
                        del st.session_state['edit_id']
                        st.experimental_rerun()
                except:
                    st.error("❌ Gagal dekripsi data. Pastikan kunci benar.")

    else:
        st.info("Belum ada data tersimpan.")

elif menu == "Dekripsi Data":
    st.subheader("🔓 Dekripsi Data Terenkripsi")
    data = ambil_semua_data()
    kunci = st.text_input("Masukkan Kunci Rahasia", type="password")

    if st.button("Tampilkan Data Didekripsi"):
        if not kunci:
            st.warning("Masukkan kunci terlebih dahulu!")
        elif data:
            for row in data:
                try:
                    nama = decrypt(row[1], kunci)
                    nik = decrypt(row[2], kunci)
                    alamat = decrypt(row[3], kunci)
                    no_hp = decrypt(row[4], kunci)
                    st.markdown(f"""
                        ✅ **ID:** {row[0]}  
                        🧑 **Nama:** {nama}  
                        🆔 **NIK:** {nik}  
                        📍 **Alamat:** {alamat}  
                        📞 **Nomor HP:** {no_hp}  
                        ---
                    """)
                except:
                    st.error(f"❌ Gagal dekripsi data dengan ID {row[0]} — kunci salah?")
        else:
            st.info("Belum ada data tersimpan.")
