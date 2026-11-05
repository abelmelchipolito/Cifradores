"""
Laboratorio de Criptografía: Alice -> Eve -> Bob
Requisitos:  pip install cryptography      (tkinter viene con Python)
Ejecutar:    python laboratorio_cripto.py
"""
import copy
import hashlib
import hmac as std_hmac
import os
import sys
import time
import tkinter as tk
from tkinter import ttk, scrolledtext

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac as c_hmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ======================================================================
#  CAPA CRIPTOGRÁFICA (sin dependencias de interfaz)
# ======================================================================
M_HASH = "SHA-256 (Hash sin llaves)"
M_GCM = "AES-GCM (Cifrado autenticado)"
M_HMAC = "HMAC-SHA256 (Simétrico)"
M_RSA = "RSA-PSS (Firma digital)"
M_KDF = "Scrypt vs SHA-256 (KDF)"
MECHANISMS = [M_HASH, M_GCM, M_HMAC, M_RSA, M_KDF]

DICTIONARY = ["123456", "password", "qwerty", "admin", "letmein",
              "hola123", "iloveyou", "abc123", "dragon", "monkey"]
TIME_WINDOW = 60  # segundos aceptados por el control de timestamp
SCRYPT_N = 2 ** 14


def scrypt_derive(password: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(password)


def make_header() -> bytes:
    """Cabecera = timestamp (8 B) + nonce/ID de mensaje (16 B). Anti-replay."""
    return int(time.time()).to_bytes(8, "big") + os.urandom(16)


class KeyBundle:
    """Material que Alice comparte con Bob por un canal seguro (fuera de banda)."""
    def __init__(self, aes_key, hmac_key, rsa_pub):
        self.aes_key, self.hmac_key, self.rsa_pub = aes_key, hmac_key, rsa_pub


class Alice:
    def __init__(self):
        self.generate_keys()

    def generate_keys(self):
        self.aes_key = AESGCM.generate_key(256)
        self.hmac_key = os.urandom(32)
        self.rsa_priv = rsa.generate_private_key(65537, 2048)  # PRIVADA: solo Alice

    def bundle_for_bob(self) -> KeyBundle:
        return KeyBundle(self.aes_key, self.hmac_key, self.rsa_priv.public_key())

    def build(self, mech: str, text: str):
        """Devuelve (paquete_público, info). El paquete es lo único que ve el canal."""
        msg = text.encode()
        if mech == M_HASH:
            pkt = {"digest": hashlib.sha256(msg).digest()}
            info = ("Ninguna (solo integridad ante errores; NO autentica)",
                    "Sin llaves | Digest 256 bits", [])
        elif mech == M_GCM:
            hdr, nonce = make_header(), os.urandom(12)
            ct = AESGCM(self.aes_key).encrypt(nonce, msg, hdr)  # ct = cifrado || tag(16B)
            pkt = {"header(AAD)": hdr, "iv": nonce, "ciphertext+tag": ct}
            info = ("Confidencialidad + Integridad + Autenticidad (+ anti-replay con AAD)",
                    "Llave AES 256 bits (secreta) | IV 96 bits | Etiqueta GCM 128 bits | AAD = timestamp+ID",
                    [self.aes_key, nonce])
        elif mech == M_HMAC:
            hdr = make_header()
            h = c_hmac.HMAC(self.hmac_key, hashes.SHA256())
            h.update(hdr + msg)
            pkt = {"header": hdr, "msg": msg, "tag": h.finalize()}
            info = ("Integridad + Autenticidad (NO confidencialidad)",
                    "Llave HMAC 256 bits (compartida) | Etiqueta 256 bits | Header timestamp+ID",
                    [self.hmac_key])
        elif mech == M_RSA:
            hdr = make_header()
            sig = self.rsa_priv.sign(hdr + msg, padding.PSS(
                padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
            pkt = {"header": hdr, "msg": msg, "signature": sig}
            info = ("Integridad + Autenticidad + No repudio (NO confidencialidad)",
                    "Llave privada RSA 2048 (solo Alice) | Llave pública (Bob/Eve) | Firma 2048 bits",
                    [sig])
        elif mech == M_KDF:
            salt = os.urandom(16)
            pkt = {"salt": salt,
                   "sha256_hash": hashlib.sha256(msg).digest(),
                   "scrypt_key": scrypt_derive(msg, salt)}
            info = ("Resistencia a fuerza bruta (costo computacional)",
                    "Salt 128 bits | SHA-256 (rápido) | Scrypt N=2^14, r=8, p=1 (lento, usa memoria)",
                    [salt])
        else:
            raise ValueError("Mecanismo desconocido")
        return pkt, info


class Eve:
    """Atacante: NO posee llaves privadas ni compartidas. Solo ve y altera tráfico."""
    def __init__(self):
        self.captured = []

    def intercept(self, pkt):
        self.captured.append(copy.deepcopy(pkt))

    @staticmethod
    def _flip(data: bytes, idx=0) -> bytes:
        b = bytearray(data)
        b[idx % len(b)] ^= 0x01
        return bytes(b)

    def alter_field(self, pkt, field):
        if field not in pkt:
            return None
        new = copy.deepcopy(pkt)
        new[field] = self._flip(new[field], len(new[field]) // 2)
        return new

    def alter_message(self, pkt):
        if "msg" in pkt:
            new = copy.deepcopy(pkt)
            new["msg"] = b"MENSAJE FALSO de Eve: transfiere $1,000,000"
            return new
        for f in ("digest", "sha256_hash"):
            if f in pkt:
                return self.alter_field(pkt, f)
        return None

    def replay(self):
        return copy.deepcopy(self.captured[-1]) if self.captured else None

    def dictionary_attack(self, pkt):
        """Devuelve lista de líneas de log. Ataca SHA-256 y/o Scrypt."""
        log = []
        target_sha = pkt.get("digest") or pkt.get("sha256_hash")
        if target_sha is None:
            return ["El paquete no contiene un hash que atacar."]
        t0 = time.perf_counter()
        found = next((w for w in DICTIONARY
                      if hashlib.sha256(w.encode()).digest() == target_sha), None)
        dt_sha = (time.perf_counter() - t0) * 1000
        log.append(f"[SHA-256] {len(DICTIONARY)} palabras en {dt_sha:.3f} ms -> "
                   + (f"¡CONTRASEÑA ENCONTRADA: '{found}'!" if found else "no encontrada"))
        if "scrypt_key" in pkt:
            t0 = time.perf_counter()
            found2 = None
            for w in DICTIONARY:
                if std_hmac.compare_digest(scrypt_derive(w.encode(), pkt["salt"]), pkt["scrypt_key"]):
                    found2 = w
                    break
            dt_sc = (time.perf_counter() - t0) * 1000
            log.append(f"[Scrypt ] mismo diccionario en {dt_sc:.1f} ms -> "
                       + (f"encontrada: '{found2}'" if found2 else "no encontrada"))
            log.append(f"Scrypt fue ~{dt_sc / max(dt_sha, 1e-6):,.0f}x más lento por intento: "
                       "frena la fuerza bruta (y el salt evita tablas precalculadas).")
        elif found:
            log.append("Lección: SHA-256 sin salt ni costo es trivial de romper con contraseñas débiles.")
        return log


class Bob:
    def __init__(self, bundle: KeyBundle):
        self.keys = bundle
        self.seen_ids = set()

    def _check_freshness(self, hdr: bytes):
        ts = int.from_bytes(hdr[:8], "big")
        if abs(time.time() - ts) > TIME_WINDOW:
            return False, f"RECHAZADO: timestamp fuera de la ventana de {TIME_WINDOW} s."
        if hdr[8:] in self.seen_ids:
            return False, "RECHAZADO: ataque de repetición (REPLAY): el nonce/ID ya fue usado."
        self.seen_ids.add(hdr[8:])
        return True, ""

    def verify(self, mech, pkt, password_try=""):
        """Devuelve (ok, explicación). Nunca lanza excepciones hacia la GUI."""
        try:
            if mech == M_HASH:
                ok = std_hmac.compare_digest(hashlib.sha256(password_try.encode()).digest(), pkt["digest"])
                return ok, ("ACEPTADO: el hash coincide con la entrada de Bob." if ok else
                            "RECHAZADO: el hash no coincide (dato alterado o entrada distinta).")
            if mech == M_KDF:
                s = std_hmac.compare_digest(hashlib.sha256(password_try.encode()).digest(), pkt["sha256_hash"])
                k = std_hmac.compare_digest(scrypt_derive(password_try.encode(), pkt["salt"]), pkt["scrypt_key"])
                return (s and k), (f"SHA-256: {'OK' if s else 'falla'} | Scrypt: {'OK' if k else 'falla'}")
            if mech == M_GCM:
                hdr = pkt["header(AAD)"]
                pt = AESGCM(self.keys.aes_key).decrypt(pkt["iv"], pkt["ciphertext+tag"], hdr)
                fresh, why = self._check_freshness(hdr)
                return (True, f"ACEPTADO. Mensaje original: «{pt.decode()}»") if fresh else (False, why)
            if mech == M_HMAC:
                h = c_hmac.HMAC(self.keys.hmac_key, hashes.SHA256())
                h.update(pkt["header"] + pkt["msg"])
                h.verify(pkt["tag"])
                fresh, why = self._check_freshness(pkt["header"])
                return (True, f"ACEPTADO: etiqueta válida. Mensaje: «{pkt['msg'].decode()}»") if fresh else (False, why)
            if mech == M_RSA:
                self.keys.rsa_pub.verify(pkt["signature"], pkt["header"] + pkt["msg"], padding.PSS(
                    padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
                fresh, why = self._check_freshness(pkt["header"])
                return (True, f"ACEPTADO: firma válida de Alice. Mensaje: «{pkt['msg'].decode()}»") if fresh else (False, why)
        except InvalidTag:
            return False, "RECHAZADO: falla de verificación AES-GCM (etiqueta inválida: cifrado/AAD alterados)."
        except InvalidSignature:
            return False, "RECHAZADO: firma/etiqueta inválida (mensaje modificado o llave incorrecta)."
        except Exception as e:  # paquete malformado, campos faltantes, etc.
            return False, f"RECHAZADO: error al procesar ({type(e).__name__}: {e})."
        return False, "Mecanismo no soportado."


# ======================================================================
#  CAPA DE INTERFAZ
# ======================================================================
def fmt_packet(pkt):
    if not pkt:
        return "(vacío)"
    lines = []
    for k, v in pkt.items():
        shown = v.hex()
        shown = shown if len(shown) <= 64 else shown[:64] + "…"
        extra = f"  \"{v.decode(errors='replace')}\"" if k == "msg" else ""
        lines.append(f"{k} [{len(v)} B]:\n  {shown}{extra}")
    return "\n".join(lines)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Laboratorio de Criptografía — Alice, Eve y Bob")
        self.geometry("1250x760")
        self.alice, self.eve = Alice(), Eve()
        self.bob = Bob(self.alice.bundle_for_bob())
        self.channel = None          # paquete en tránsito
        self.mech = M_GCM
        self._build_ui()

    # ---------- construcción ----------
    def _box(self, parent, h):
        w = scrolledtext.ScrolledText(parent, height=h, width=44, font=("Consolas", 9), wrap="word")
        w.configure(state="disabled")
        return w

    def _build_ui(self):
        top = ttk.LabelFrame(self, text=" Métricas de la operación ")
        top.pack(fill="x", padx=8, pady=6)
        self.v_prop, self.v_comp, self.v_res = tk.StringVar(value="—"), tk.StringVar(value="—"), tk.StringVar(value="—")
        for i, (t, v) in enumerate((("Propiedad:", self.v_prop), ("Componentes:", self.v_comp), ("Recursos:", self.v_res))):
            ttk.Label(top, text=t, font=("Segoe UI", 9, "bold")).grid(row=i, column=0, sticky="w", padx=6)
            ttk.Label(top, textvariable=v, wraplength=1100).grid(row=i, column=1, sticky="w")

        cols = ttk.Frame(self)
        cols.pack(fill="both", expand=True, padx=8, pady=4)
        for c in range(3):
            cols.columnconfigure(c, weight=1, uniform="c")
        cols.rowconfigure(0, weight=1)

        # --- Alice ---
        fa = ttk.LabelFrame(cols, text=" Alice (Emisor) ")
        fa.grid(row=0, column=0, sticky="nsew", padx=4)
        ttk.Label(fa, text="Mensaje (o contraseña en Hash/KDF):").pack(anchor="w", padx=6)
        self.e_msg = ttk.Entry(fa)
        self.e_msg.insert(0, "Transferir $100 a Bob")
        self.e_msg.pack(fill="x", padx=6, pady=3)
        self.cb = ttk.Combobox(fa, values=MECHANISMS, state="readonly")
        self.cb.set(self.mech)
        self.cb.pack(fill="x", padx=6, pady=3)
        ttk.Button(fa, text="Generar claves nuevas", command=self.on_keys).pack(fill="x", padx=6, pady=2)
        ttk.Button(fa, text="Ejecutar y enviar al canal ▶", command=self.on_send).pack(fill="x", padx=6, pady=2)
        ttk.Label(fa, text="Datos enviados al canal:").pack(anchor="w", padx=6)
        self.t_alice = self._box(fa, 20)
        self.t_alice.pack(fill="both", expand=True, padx=6, pady=4)

        # --- Eve ---
        fe = ttk.LabelFrame(cols, text=" Eve (Atacante / Canal) — solo datos públicos ")
        fe.grid(row=0, column=1, sticky="nsew", padx=4)
        ttk.Label(fe, text="Interceptado:").pack(anchor="w", padx=6)
        self.t_eve = self._box(fe, 9)
        self.t_eve.pack(fill="x", padx=6, pady=2)
        attacks = [("1. Ataque de diccionario (contra hash)", self.atk_dict),
                   ("2a. Alterar 1 byte del cifrado (AES-GCM)", lambda: self.atk_flip("ciphertext+tag", "cifrado")),
                   ("2b. Alterar 1 byte del AAD (AES-GCM)", lambda: self.atk_flip("header(AAD)", "AAD")),
                   ("3. Modificar mensaje (HMAC / Firma / Hash)", self.atk_msg),
                   ("4. Replay: reenviar mensaje interceptado", self.atk_replay)]
        for txt, cmd in attacks:
            ttk.Button(fe, text=txt, command=cmd).pack(fill="x", padx=6, pady=2)
        ttk.Label(fe, text="Bitácora de Eve:").pack(anchor="w", padx=6)
        self.t_log = self._box(fe, 9)
        self.t_log.pack(fill="both", expand=True, padx=6, pady=4)

        # --- Bob ---
        fb = ttk.LabelFrame(cols, text=" Bob (Receptor) ")
        fb.grid(row=0, column=2, sticky="nsew", padx=4)
        ttk.Label(fb, text="Recibido del canal:").pack(anchor="w", padx=6)
        self.t_bob = self._box(fb, 12)
        self.t_bob.pack(fill="x", padx=6, pady=2)
        ttk.Label(fb, text="Contraseña a probar (solo Hash/KDF):").pack(anchor="w", padx=6)
        self.e_try = ttk.Entry(fb)
        self.e_try.pack(fill="x", padx=6, pady=2)
        ttk.Button(fb, text="Descifrar / Verificar ✔", command=self.on_verify).pack(fill="x", padx=6, pady=4)
        self.lbl_res = tk.Label(fb, text="Esperando mensaje…", bg="#888", fg="white",
                                font=("Segoe UI", 12, "bold"), wraplength=360, height=6)
        self.lbl_res.pack(fill="x", padx=6, pady=6)
        ttk.Label(fb, text="Tip: verifica el original primero y luego usa Replay.",
                  foreground="#555").pack(padx=6)

    # ---------- utilidades ----------
    @staticmethod
    def _set(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def _log(self, text):
        self.t_log.configure(state="normal")
        self.t_log.insert("end", text + "\n")
        self.t_log.see("end")
        self.t_log.configure(state="disabled")

    def _refresh_channel(self):
        self._set(self.t_eve, fmt_packet(self.channel) + "\n\n(Eve tiene solo la llave pública RSA)")
        self._set(self.t_bob, fmt_packet(self.channel))

    # ---------- acciones de Alice ----------
    def on_keys(self):
        try:
            t0 = time.perf_counter()
            self.alice.generate_keys()
            self.bob = Bob(self.alice.bundle_for_bob())   # nuevo canal seguro de llaves
            dt = (time.perf_counter() - t0) * 1000
            self.v_res.set(f"Generación de llaves AES/HMAC/RSA-2048: {dt:.1f} ms")
            self._log("Alice regeneró llaves. Eve no recibe ninguna.")
        except Exception as e:
            self._log(f"Error: {e}")

    def on_send(self):
        try:
            self.mech = self.cb.get()
            t0 = time.perf_counter()
            pkt, (prop, comp, secret_objs) = self.alice.build(self.mech, self.e_msg.get())
            dt = (time.perf_counter() - t0) * 1000
            mem = sum(sys.getsizeof(v) for v in pkt.values()) + sum(sys.getsizeof(o) for o in secret_objs)
            self.v_prop.set(prop)
            self.v_comp.set(comp)
            self.v_res.set(f"Tiempo (Alice): {dt:.3f} ms | Memoria estimada (sys.getsizeof): {mem} bytes")
            self.channel = pkt
            self.eve.intercept(pkt)
            self._set(self.t_alice, fmt_packet(pkt))
            self._refresh_channel()
            self._log(f"Eve interceptó un paquete ({self.mech}).")
            self.lbl_res.config(text="Mensaje recibido.\nPresiona Verificar.", bg="#888")
        except Exception as e:
            self._log(f"Error en Alice: {e}")

    # ---------- ataques de Eve ----------
    def _need_packet(self):
        if self.channel is None:
            self._log("No hay tráfico interceptado todavía.")
            return False
        return True

    def atk_dict(self):
        if not self._need_packet():
            return
        for line in self.eve.dictionary_attack(self.channel):
            self._log(line)

    def atk_flip(self, field, name):
        if not self._need_packet():
            return
        new = self.eve.alter_field(self.channel, field)
        if new is None:
            self._log(f"Ataque no aplicable: este mecanismo no tiene campo '{field}'.")
            return
        self.channel = new
        self._refresh_channel()
        self._log(f"Eve alteró 1 bit/byte del {name} en tránsito.")

    def atk_msg(self):
        if not self._need_packet():
            return
        new = self.eve.alter_message(self.channel)
        if new is None:
            self._log("Ataque no aplicable: el mensaje viaja cifrado o no hay mensaje en claro.")
            return
        self.channel = new
        self._refresh_channel()
        self._log("Eve modificó el mensaje SIN conocer ninguna llave.")

    def atk_replay(self):
        old = self.eve.replay()
        if old is None:
            self._log("Eve no ha capturado nada para repetir.")
            return
        self.channel = old
        self._refresh_channel()
        self._log("Eve reenvió un paquete previamente capturado (replay).")

    # ---------- Bob ----------
    def on_verify(self):
        if self.channel is None:
            self.lbl_res.config(text="No hay mensajes.", bg="#888")
            return
        t0 = time.perf_counter()
        ok, why = self.bob.verify(self.mech, self.channel, self.e_try.get())
        dt = (time.perf_counter() - t0) * 1000
        self.lbl_res.config(text=("✔ " if ok else "✖ ") + why, bg="#2e9e4f" if ok else "#c0392b")
        self.v_res.set(self.v_res.get().split(" | Bob")[0] + f" | Bob: {dt:.3f} ms")


if __name__ == "__main__":
    App().mainloop()