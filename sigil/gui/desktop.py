#!/usr/bin/env python3
"""
SIGIL Desktop v3 - Hardware Wallet GUI
=======================================

Connects to sigil_web JSON API endpoints.
No SE050 lock conflicts.
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import threading
import json
import sys
import os
from typing import Optional, Dict, List

from sigil.gui.api_client import SigilAPI, make_qr, HAS_QR

VERSION = "3.0.0"


# ============================================================================
#                              GUI
# ============================================================================

class SigilDesktop:
    def __init__(self, root: tk.Tk, host: str, port: int):
        self.root = root
        self.api = SigilAPI(f"http://{host}:{port}")

        self.root.title(f"SIGIL Desktop v{VERSION}")
        self.root.geometry("950x700")
        self.root.minsize(850, 600)

        # Colors
        self.C = {
            'bg': '#0a0a0f', 'card': '#12121a', 'light': '#1a1a25', 'input': '#0d0d14',
            'accent': '#f7931a', 'green': '#00d4aa', 'red': '#ff4757', 'blue': '#3498db',
            'purple': '#9b59b6', 'text': '#ffffff', 'dim': '#888888', 'border': '#2a2a3a'
        }
        self.root.configure(bg=self.C['bg'])

        # State
        self.qr_img = None
        self.address = ""

        self.show_login()

    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    # ===== LOGIN =====
    def show_login(self):
        self.clear()
        f = tk.Frame(self.root, bg=self.C['bg'])
        f.place(relx=0.5, rely=0.5, anchor='center')

        tk.Label(f, text="\u26a1 SIGIL", font=('Courier New', 40, 'bold'),
                fg=self.C['accent'], bg=self.C['bg']).pack()
        tk.Label(f, text="Desktop", font=('Courier New', 16),
                fg=self.C['dim'], bg=self.C['bg']).pack(pady=(0, 30))

        self.login_msg = tk.Label(f, text="", font=('Segoe UI', 10),
                                  fg=self.C['green'], bg=self.C['bg'])
        self.login_msg.pack(pady=(0, 10))

        tk.Label(f, text="Password", font=('Segoe UI', 10),
                fg=self.C['dim'], bg=self.C['bg']).pack(anchor='w')
        self.pw_entry = tk.Entry(f, show="\u2022", font=('Segoe UI', 14), width=25,
                                 bg=self.C['input'], fg=self.C['text'],
                                 insertbackground=self.C['accent'], relief='flat')
        self.pw_entry.pack(pady=(5, 20), ipady=10)
        self.pw_entry.bind('<Return>', lambda e: self.do_login())
        self.pw_entry.focus()

        tk.Button(f, text="UNLOCK", font=('Segoe UI', 12, 'bold'),
                 bg=self.C['accent'], fg='#000', relief='flat', cursor='hand2',
                 command=self.do_login).pack(ipadx=40, ipady=10)

        tk.Label(f, text=f"Backend: {self.api.base_url}", font=('Courier New', 9),
                fg=self.C['dim'], bg=self.C['bg']).pack(pady=(30, 0))

        self.check_conn()

    def check_conn(self):
        def chk():
            ok = self.api.check_connection()
            self.root.after(0, lambda: self.login_msg.config(
                text="\u2713 Connected" if ok else "\u2717 Cannot reach sigil_web",
                fg=self.C['green'] if ok else self.C['red']))
        threading.Thread(target=chk, daemon=True).start()

    def do_login(self):
        pw = self.pw_entry.get()
        if not pw:
            self.login_msg.config(text="Enter password", fg=self.C['red'])
            return
        self.login_msg.config(text="Logging in...", fg=self.C['dim'])

        def attempt():
            ok = self.api.login(pw)
            self.root.after(0, lambda: self.on_login(ok))
        threading.Thread(target=attempt, daemon=True).start()

    def on_login(self, ok: bool):
        if ok:
            self.show_main()
        else:
            self.login_msg.config(text="Invalid password", fg=self.C['red'])
            self.pw_entry.delete(0, tk.END)

    # ===== MAIN =====
    def show_main(self):
        self.clear()

        # Header
        hdr = tk.Frame(self.root, bg=self.C['card'], height=50)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)

        tk.Label(hdr, text="\u26a1 SIGIL", font=('Courier New', 16, 'bold'),
                fg=self.C['accent'], bg=self.C['card']).pack(side='left', padx=15, pady=10)

        tk.Button(hdr, text="Logout", font=('Segoe UI', 9),
                 bg=self.C['light'], fg=self.C['dim'], relief='flat',
                 command=self.do_logout).pack(side='right', padx=15)

        self.status_lbl = tk.Label(hdr, text="\u25cf Online", font=('Segoe UI', 9),
                                   fg=self.C['green'], bg=self.C['card'])
        self.status_lbl.pack(side='right', padx=5)

        # Tabs
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=self.C['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=self.C['card'], foreground=self.C['dim'],
                       padding=[18, 8], font=('Segoe UI', 10, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', self.C['light'])],
                 foreground=[('selected', self.C['accent'])])

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill='both', expand=True, padx=8, pady=8)

        self.tab_wallet()
        self.tab_send()
        self.tab_history()
        self.tab_tumbler()
        self.tab_tools()
        self.tab_logs()

        self.refresh_wallet()

    def do_logout(self):
        self.api.logout()
        self.show_login()

    # ===== WALLET TAB =====
    def tab_wallet(self):
        t = tk.Frame(self.nb, bg=self.C['bg'])
        self.nb.add(t, text='  \U0001f4b0 Wallet  ')

        left = tk.Frame(t, bg=self.C['bg'])
        left.pack(side='left', fill='both', expand=True, padx=(12, 6), pady=12)

        right = tk.Frame(t, bg=self.C['bg'])
        right.pack(side='right', fill='both', expand=True, padx=(6, 12), pady=12)

        # Balance
        bc = tk.Frame(left, bg=self.C['card'], padx=20, pady=18)
        bc.pack(fill='x', pady=(0, 12))

        tk.Label(bc, text="BALANCE", font=('Segoe UI', 9, 'bold'),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')

        self.bal_lbl = tk.Label(bc, text="Loading...", font=('Courier New', 28, 'bold'),
                                fg=self.C['accent'], bg=self.C['card'])
        self.bal_lbl.pack(anchor='w', pady=(8, 0))

        self.btc_lbl = tk.Label(bc, text="", font=('Courier New', 11),
                                fg=self.C['dim'], bg=self.C['card'])
        self.btc_lbl.pack(anchor='w')

        self.usd_lbl = tk.Label(bc, text="", font=('Segoe UI', 10),
                                fg=self.C['green'], bg=self.C['card'])
        self.usd_lbl.pack(anchor='w', pady=(5, 0))

        # Address
        ac = tk.Frame(left, bg=self.C['card'], padx=20, pady=18)
        ac.pack(fill='x')

        tk.Label(ac, text="RECEIVE ADDRESS", font=('Segoe UI', 9, 'bold'),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')

        self.addr_lbl = tk.Label(ac, text="Loading...", font=('Courier New', 10),
                                 fg=self.C['blue'], bg=self.C['card'], wraplength=320)
        self.addr_lbl.pack(anchor='w', pady=(10, 10))

        bf = tk.Frame(ac, bg=self.C['card'])
        bf.pack(anchor='w')
        tk.Button(bf, text="\U0001f4cb Copy", font=('Segoe UI', 9), bg=self.C['light'],
                 fg=self.C['text'], relief='flat', command=self.copy_addr).pack(side='left', padx=(0, 8))
        tk.Button(bf, text="\u21bb Refresh", font=('Segoe UI', 9), bg=self.C['light'],
                 fg=self.C['text'], relief='flat', command=self.refresh_wallet).pack(side='left')

        # QR
        qc = tk.Frame(right, bg=self.C['card'], padx=20, pady=18)
        qc.pack(fill='both', expand=True)

        tk.Label(qc, text="QR CODE", font=('Segoe UI', 9, 'bold'),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')

        self.qr_lbl = tk.Label(qc, bg=self.C['card'], text="(loading)" if HAS_QR else "(QR unavailable)")
        self.qr_lbl.pack(pady=15)

    def refresh_wallet(self):
        def fetch():
            data = self.api.get_status()
            self.root.after(0, lambda: self.update_wallet(data))
        threading.Thread(target=fetch, daemon=True).start()

    def update_wallet(self, data: Dict):
        sats = data.get('balance_sats', 0)
        self.bal_lbl.config(text=f"{sats:,} sats")
        self.btc_lbl.config(text=f"{data.get('balance_btc', '0.00000000')} BTC")

        usd = data.get('usd_value', '0.00')
        if float(usd) > 0:
            self.usd_lbl.config(text=f"\u2248 ${usd} USD")

        addr = data.get('address', '')
        if addr:
            self.address = addr
            self.addr_lbl.config(text=addr)
            if HAS_QR:
                self.qr_img = make_qr(f"bitcoin:{addr}", 180)
                if self.qr_img:
                    self.qr_lbl.config(image=self.qr_img, text="")

    def copy_addr(self):
        if self.address:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.address)
            messagebox.showinfo("Copied", "Address copied!")

    # ===== SEND TAB =====
    def tab_send(self):
        t = tk.Frame(self.nb, bg=self.C['bg'])
        self.nb.add(t, text='  \U0001f4e4 Send  ')
        self.send_frame = t

        # Balance display
        bal_f = tk.Frame(t, bg=self.C['card'], padx=20, pady=12)
        bal_f.pack(fill='x', padx=15, pady=(12, 8))

        tk.Label(bal_f, text="AVAILABLE", font=('Segoe UI', 9, 'bold'),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')
        self.send_bal_lbl = tk.Label(bal_f, text="Loading...", font=('Courier New', 14),
                                     fg=self.C['green'], bg=self.C['card'])
        self.send_bal_lbl.pack(anchor='w')

        # Form
        f = tk.Frame(t, bg=self.C['card'], padx=25, pady=20)
        f.pack(fill='x', padx=15, pady=(0, 8))

        tk.Label(f, text="SEND BITCOIN", font=('Segoe UI', 12, 'bold'),
                fg=self.C['accent'], bg=self.C['card']).pack(anchor='w', pady=(0, 15))

        # Recipient
        tk.Label(f, text="Recipient Address", font=('Segoe UI', 9),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')
        self.send_addr = tk.Entry(f, font=('Courier New', 11), bg=self.C['input'],
                                  fg=self.C['text'], insertbackground=self.C['accent'], relief='flat')
        self.send_addr.pack(fill='x', pady=(4, 12), ipady=8)

        # Amount row
        amt_row = tk.Frame(f, bg=self.C['card'])
        amt_row.pack(fill='x', pady=(0, 12))

        amt_left = tk.Frame(amt_row, bg=self.C['card'])
        amt_left.pack(side='left', fill='x', expand=True)
        tk.Label(amt_left, text="Amount (sats)", font=('Segoe UI', 9),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')
        self.send_amt = tk.Entry(amt_left, font=('Courier New', 11), bg=self.C['input'],
                                 fg=self.C['text'], insertbackground=self.C['accent'], relief='flat', width=18)
        self.send_amt.pack(anchor='w', pady=(4, 0), ipady=8)

        self.send_max_var = tk.BooleanVar()
        tk.Checkbutton(amt_row, text="Send Max", variable=self.send_max_var,
                      font=('Segoe UI', 9), bg=self.C['card'], fg=self.C['text'],
                      selectcolor=self.C['input'], activebackground=self.C['card'],
                      command=self.toggle_send_max).pack(side='right', padx=(15, 0), pady=(20, 0))

        # Fee rate
        tk.Label(f, text="Fee Rate (sat/vB)", font=('Segoe UI', 9),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')

        fee_row = tk.Frame(f, bg=self.C['card'])
        fee_row.pack(fill='x', pady=(4, 12))

        self.send_fee = tk.Entry(fee_row, font=('Courier New', 11), bg=self.C['input'],
                                 fg=self.C['text'], insertbackground=self.C['accent'],
                                 relief='flat', width=8)
        self.send_fee.pack(side='left', ipady=8)
        self.send_fee.insert(0, "10")

        self.fee_hint = tk.Label(fee_row, text="", font=('Segoe UI', 8),
                                 fg=self.C['dim'], bg=self.C['card'])
        self.fee_hint.pack(side='left', padx=(10, 0))

        # Signing PIN
        tk.Label(f, text="Signing PIN (if enabled)", font=('Segoe UI', 9),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')
        self.send_pin = tk.Entry(f, font=('Courier New', 11), bg=self.C['input'],
                                 fg=self.C['text'], insertbackground=self.C['accent'],
                                 relief='flat', show="\u2022", width=12)
        self.send_pin.pack(anchor='w', pady=(4, 15), ipady=8)

        # Buttons
        btn_row = tk.Frame(f, bg=self.C['card'])
        btn_row.pack(fill='x')

        tk.Button(btn_row, text="PREPARE TX", font=('Segoe UI', 11, 'bold'),
                 bg=self.C['accent'], fg='#000', relief='flat', cursor='hand2',
                 command=self.prepare_send).pack(side='left', ipadx=25, ipady=10)

        self.send_status = tk.Label(btn_row, text="", font=('Segoe UI', 9),
                                    fg=self.C['dim'], bg=self.C['card'])
        self.send_status.pack(side='left', padx=(15, 0))

        # Load balance and fees
        self.refresh_send_info()

    def toggle_send_max(self):
        if self.send_max_var.get():
            self.send_amt.delete(0, tk.END)
            self.send_amt.config(state='disabled')
        else:
            self.send_amt.config(state='normal')

    def refresh_send_info(self):
        def fetch():
            bal = self.api.get_balance()
            fees = self.api.get_fees()
            self.root.after(0, lambda: self.update_send_info(bal, fees))
        threading.Thread(target=fetch, daemon=True).start()

    def update_send_info(self, bal: Dict, fees: Dict):
        balance = bal.get('balance', 0)
        utxos = bal.get('utxo_count', 0)
        self.send_bal_lbl.config(text=f"{balance:,} sats ({utxos} UTXOs)")

        fast = fees.get('fastestFee', 20)
        med = fees.get('halfHourFee', 10)
        slow = fees.get('hourFee', 5)
        self.fee_hint.config(text=f"Fast:{fast} Med:{med} Slow:{slow}")

    def prepare_send(self):
        addr = self.send_addr.get().strip()
        if not addr:
            messagebox.showerror("Error", "Enter recipient address")
            return

        send_max = self.send_max_var.get()

        if not send_max:
            try:
                amount = int(self.send_amt.get())
                if amount < 546:
                    messagebox.showerror("Error", "Amount too small (dust)")
                    return
            except:
                messagebox.showerror("Error", "Invalid amount")
                return
        else:
            amount = 0

        try:
            fee_rate = int(self.send_fee.get())
        except:
            messagebox.showerror("Error", "Invalid fee rate")
            return

        pin = self.send_pin.get()

        self.send_status.config(text="Signing...", fg=self.C['accent'])

        def do_prepare():
            result = self.api.prepare_send(addr, amount, fee_rate, pin, send_max)
            self.root.after(0, lambda: self.on_tx_prepared(result))

        threading.Thread(target=do_prepare, daemon=True).start()

    def on_tx_prepared(self, result: Dict):
        self.send_status.config(text="")

        if result.get('error'):
            messagebox.showerror("Error", result['error'])
            return

        # Show confirmation dialog
        tx_hex = result.get('tx_hex', '')
        to_addr = result.get('to_address', '')
        amount = result.get('amount', 0)
        fee = result.get('fee', 0)

        msg = f"""Confirm Transaction:

To: {to_addr}
Amount: {amount:,} sats
Fee: {fee:,} sats
Total: {amount + fee:,} sats

Broadcast this transaction?"""

        if messagebox.askyesno("Confirm Send", msg):
            self.broadcast_tx(tx_hex)

    def broadcast_tx(self, tx_hex: str):
        self.send_status.config(text="Broadcasting...", fg=self.C['accent'])

        def do_broadcast():
            result = self.api.broadcast_tx(tx_hex)
            self.root.after(0, lambda: self.on_broadcast(result))

        threading.Thread(target=do_broadcast, daemon=True).start()

    def on_broadcast(self, result: Dict):
        self.send_status.config(text="")

        if result.get('error'):
            messagebox.showerror("Broadcast Failed", result['error'])
        else:
            txid = result.get('txid', '')
            messagebox.showinfo("Success", f"TX Broadcast! TXID: {txid}")
            # Clear form
            self.send_addr.delete(0, tk.END)
            self.send_amt.config(state='normal')
            self.send_amt.delete(0, tk.END)
            self.send_max_var.set(False)
            self.send_pin.delete(0, tk.END)
            # Refresh balance
            self.refresh_send_info()
            self.refresh_wallet()

    # ===== HISTORY TAB =====
    def tab_history(self):
        t = tk.Frame(self.nb, bg=self.C['bg'])
        self.nb.add(t, text='  \U0001f4dc History  ')

        hdr = tk.Frame(t, bg=self.C['bg'])
        hdr.pack(fill='x', padx=15, pady=(12, 8))

        tk.Label(hdr, text="TRANSACTIONS", font=('Segoe UI', 11, 'bold'),
                fg=self.C['accent'], bg=self.C['bg']).pack(side='left')

        tk.Button(hdr, text="\u21bb Refresh", font=('Segoe UI', 9), bg=self.C['light'],
                 fg=self.C['text'], relief='flat', command=self.refresh_history).pack(side='right')

        self.hist_txt = scrolledtext.ScrolledText(t, font=('Courier New', 10),
                                                  bg=self.C['card'], fg=self.C['text'], relief='flat')
        self.hist_txt.pack(fill='both', expand=True, padx=15, pady=(0, 12))

    def refresh_history(self):
        def fetch():
            txs = self.api.get_history()
            self.root.after(0, lambda: self.update_history(txs))
        threading.Thread(target=fetch, daemon=True).start()

    def update_history(self, txs: List[Dict]):
        self.hist_txt.config(state='normal')
        self.hist_txt.delete('1.0', tk.END)
        if not txs:
            self.hist_txt.insert(tk.END, "No transactions yet.")
        else:
            for tx in txs:
                status = "\u2713" if tx.get('confirmed') else "\u25cb"
                val = tx.get('value', 0)
                self.hist_txt.insert(tk.END, f"{status} {tx['txid'][:16]}...  {val:>10} sats\n")
        self.hist_txt.config(state='disabled')

    # ===== TUMBLER TAB =====
    def tab_tumbler(self):
        t = tk.Frame(self.nb, bg=self.C['bg'])
        self.nb.add(t, text='  \U0001f300 Tumbler  ')
        self.tumbler_frame = t

        # Header warning
        w = tk.Frame(t, bg='#2a1515', padx=15, pady=10)
        w.pack(fill='x', padx=12, pady=(12, 8))
        tk.Label(w, text="\u26a0\ufe0f COIN TUMBLER", font=('Segoe UI', 11, 'bold'),
                fg=self.C['red'], bg='#2a1515').pack(anchor='w')
        tk.Label(w, text="Break transaction graph - coins hop through temp wallets",
                font=('Segoe UI', 9), fg='#aa6666', bg='#2a1515').pack(anchor='w')

        # Main content area
        self.tumbler_content = tk.Frame(t, bg=self.C['bg'])
        self.tumbler_content.pack(fill='both', expand=True, padx=12, pady=8)

        self.refresh_tumbler()

    def refresh_tumbler(self):
        def fetch():
            data = self.api.get_tumbler()
            self.root.after(0, lambda: self.render_tumbler(data))
        threading.Thread(target=fetch, daemon=True).start()

    def render_tumbler(self, data: Dict):
        for w in self.tumbler_content.winfo_children():
            w.destroy()

        status = data.get('status', 'idle')

        if status == 'idle':
            self.render_tumbler_idle()
        elif status == 'waiting_deposit':
            self.render_tumbler_waiting(data)
        elif status == 'tumbling':
            self.render_tumbler_active(data)
        elif status == 'complete':
            self.render_tumbler_complete(data)
        elif status == 'failed':
            self.render_tumbler_failed(data)
        else:
            self.render_tumbler_idle()

    def render_tumbler_idle(self):
        f = tk.Frame(self.tumbler_content, bg=self.C['card'], padx=25, pady=20)
        f.pack(fill='x', pady=10)

        tk.Label(f, text="Start New Tumble", font=('Segoe UI', 14, 'bold'),
                fg=self.C['text'], bg=self.C['card']).pack(anchor='w', pady=(0, 15))

        tk.Label(f, text="Delay Between Hops", font=('Segoe UI', 10),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')

        self.tumble_delay = ttk.Combobox(f, values=['fast', 'normal', 'stealth', 'paranoid'],
                                         state='readonly', width=20, font=('Segoe UI', 11))
        self.tumble_delay.set('normal')
        self.tumble_delay.pack(anchor='w', pady=(5, 5))

        delays = {'fast': '1-5 min', 'normal': '10-30 min', 'stealth': '1-6 hours', 'paranoid': '6-24 hours'}
        self.delay_desc = tk.Label(f, text="10-30 minutes between hops", font=('Segoe UI', 9),
                                   fg=self.C['dim'], bg=self.C['card'])
        self.delay_desc.pack(anchor='w', pady=(0, 20))

        def update_desc(e=None):
            sel = self.tumble_delay.get()
            self.delay_desc.config(text=f"{delays.get(sel, '')} between hops")
        self.tumble_delay.bind('<<ComboboxSelected>>', update_desc)

        tk.Button(f, text="Generate Tumble Address", font=('Segoe UI', 11, 'bold'),
                 bg=self.C['accent'], fg='#000', relief='flat', cursor='hand2',
                 command=self.start_tumble).pack(anchor='w', ipadx=20, ipady=8)

    def render_tumbler_waiting(self, data: Dict):
        info = tk.Frame(self.tumbler_content, bg='#1a2a1a', padx=15, pady=12)
        info.pack(fill='x', pady=(0, 10))
        tk.Label(info, text="\u23f3 Waiting for deposit...", font=('Segoe UI', 11, 'bold'),
                fg=self.C['green'], bg='#1a2a1a').pack(anchor='w')
        tk.Label(info, text="Send coins to the address below. Tumbling begins on confirmation.",
                font=('Segoe UI', 9), fg='#66aa66', bg='#1a2a1a').pack(anchor='w')

        addr_card = tk.Frame(self.tumbler_content, bg=self.C['card'], padx=20, pady=15)
        addr_card.pack(fill='x', pady=5)

        tk.Label(addr_card, text="DEPOSIT ADDRESS", font=('Segoe UI', 9, 'bold'),
                fg=self.C['dim'], bg=self.C['card']).pack(anchor='w')

        addr = data.get('deposit_address', '')
        addr_f = tk.Frame(addr_card, bg=self.C['card'])
        addr_f.pack(fill='x', pady=(8, 0))

        tk.Label(addr_f, text=addr, font=('Courier New', 11),
                fg=self.C['accent'], bg=self.C['card']).pack(side='left')

        def copy_addr():
            self.root.clipboard_clear()
            self.root.clipboard_append(addr)

        tk.Button(addr_f, text="Copy", font=('Segoe UI', 9),
                 bg=self.C['light'], fg=self.C['text'], relief='flat',
                 command=copy_addr).pack(side='right')

        if HAS_QR and addr:
            qr_f = tk.Frame(self.tumbler_content, bg=self.C['card'], padx=20, pady=15)
            qr_f.pack(fill='x', pady=5)
            qr_img = make_qr(f"bitcoin:{addr}", 180)
            if qr_img:
                qr_lbl = tk.Label(qr_f, image=qr_img, bg=self.C['card'])
                qr_lbl.image = qr_img
                qr_lbl.pack()

        det = tk.Frame(self.tumbler_content, bg=self.C['card'], padx=20, pady=15)
        det.pack(fill='x', pady=5)

        for label, value in [("Job ID", data.get('job_id', 'N/A')),
                             ("Delay", data.get('delay_preset', 'normal')),
                             ("Hops", str(data.get('total_hops', 3)))]:
            row = tk.Frame(det, bg=self.C['card'])
            row.pack(fill='x', pady=2)
            tk.Label(row, text=label+":", font=('Segoe UI', 10),
                    fg=self.C['dim'], bg=self.C['card'], width=10, anchor='w').pack(side='left')
            tk.Label(row, text=value, font=('Courier New', 10),
                    fg=self.C['text'], bg=self.C['card']).pack(side='left')

        tk.Button(self.tumbler_content, text="Cancel & Cleanup", font=('Segoe UI', 10),
                 bg=self.C['red'], fg='#fff', relief='flat', cursor='hand2',
                 command=self.cancel_tumble).pack(anchor='w', pady=15, ipadx=15, ipady=6)

    def render_tumbler_active(self, data: Dict):
        prog = tk.Frame(self.tumbler_content, bg='#2a2a1a', padx=15, pady=12)
        prog.pack(fill='x', pady=(0, 10))
        tk.Label(prog, text="\U0001f300 Tumbling in progress...", font=('Segoe UI', 11, 'bold'),
                fg=self.C['accent'], bg='#2a2a1a').pack(anchor='w')

        stats = tk.Frame(self.tumbler_content, bg=self.C['card'], padx=20, pady=15)
        stats.pack(fill='x', pady=5)

        current = data.get('current_hop', 0) + 1
        total = data.get('total_hops', 3) + 1
        amount = data.get('amount_sats', 0)

        for label, value in [("Amount", f"{amount:,} sats"),
                             ("Progress", f"Hop {current} / {total}"),
                             ("Next Hop", data.get('next_hop_time', 'Processing...')[:19] if data.get('next_hop_time') else 'Processing...')]:
            row = tk.Frame(stats, bg=self.C['card'])
            row.pack(fill='x', pady=4)
            tk.Label(row, text=label, font=('Segoe UI', 10, 'bold'),
                    fg=self.C['dim'], bg=self.C['card'], width=12, anchor='w').pack(side='left')
            tk.Label(row, text=value, font=('Courier New', 11),
                    fg=self.C['green'] if 'Hop' in label else self.C['text'],
                    bg=self.C['card']).pack(side='left')

        txids = data.get('txids', [])
        if txids:
            tx_f = tk.Frame(self.tumbler_content, bg=self.C['card'], padx=20, pady=15)
            tx_f.pack(fill='x', pady=5)
            tk.Label(tx_f, text="TRANSACTION CHAIN", font=('Segoe UI', 9, 'bold'),
                    fg=self.C['dim'], bg=self.C['card']).pack(anchor='w', pady=(0, 8))
            for i, txid in enumerate(txids):
                tk.Label(tx_f, text=f"Hop {i+1}: {txid[:24]}...",
                        font=('Courier New', 9), fg=self.C['blue'],
                        bg=self.C['card']).pack(anchor='w')

    def render_tumbler_complete(self, data: Dict):
        ok = tk.Frame(self.tumbler_content, bg='#1a2a1a', padx=15, pady=12)
        ok.pack(fill='x', pady=(0, 10))
        tk.Label(ok, text="\u2705 Tumble Complete!", font=('Segoe UI', 12, 'bold'),
                fg=self.C['green'], bg='#1a2a1a').pack(anchor='w')

        amount = data.get('amount_sats', 0)
        tk.Label(ok, text=f"{amount:,} sats delivered to your main wallet",
                font=('Segoe UI', 10), fg='#66aa66', bg='#1a2a1a').pack(anchor='w')

        txids = data.get('txids', [])
        if txids:
            tx_f = tk.Frame(self.tumbler_content, bg=self.C['card'], padx=20, pady=15)
            tx_f.pack(fill='x', pady=5)
            tk.Label(tx_f, text="TRANSACTION CHAIN", font=('Segoe UI', 9, 'bold'),
                    fg=self.C['dim'], bg=self.C['card']).pack(anchor='w', pady=(0, 8))
            for i, txid in enumerate(txids):
                tk.Label(tx_f, text=f"Hop {i+1}: {txid[:32]}...",
                        font=('Courier New', 9), fg=self.C['blue'],
                        bg=self.C['card']).pack(anchor='w', pady=1)

        tk.Button(self.tumbler_content, text="Cleanup & Start New", font=('Segoe UI', 11, 'bold'),
                 bg=self.C['accent'], fg='#000', relief='flat', cursor='hand2',
                 command=self.cleanup_tumble).pack(anchor='w', pady=15, ipadx=20, ipady=8)

    def render_tumbler_failed(self, data: Dict):
        err = tk.Frame(self.tumbler_content, bg='#2a1515', padx=15, pady=12)
        err.pack(fill='x', pady=(0, 10))
        tk.Label(err, text="\u274c Tumble Failed", font=('Segoe UI', 12, 'bold'),
                fg=self.C['red'], bg='#2a1515').pack(anchor='w')
        tk.Label(err, text=data.get('error', 'Unknown error'),
                font=('Segoe UI', 10), fg='#aa6666', bg='#2a1515').pack(anchor='w')

        tk.Button(self.tumbler_content, text="Cleanup & Reset", font=('Segoe UI', 10),
                 bg=self.C['red'], fg='#fff', relief='flat', cursor='hand2',
                 command=self.cancel_tumble).pack(anchor='w', pady=15, ipadx=15, ipady=6)

    def start_tumble(self):
        delay = self.tumble_delay.get() if hasattr(self, 'tumble_delay') else 'normal'

        def do_start():
            result = self.api.start_tumble(delay)
            self.root.after(0, lambda: self.on_tumble_started(result))

        threading.Thread(target=do_start, daemon=True).start()

    def on_tumble_started(self, result: Dict):
        if result.get('error'):
            messagebox.showerror("Error", result['error'])
        else:
            self.refresh_tumbler()

    def cancel_tumble(self):
        if not messagebox.askyesno("Confirm", "Cancel tumble and delete temporary keys?"):
            return

        def do_cancel():
            result = self.api.cancel_tumble()
            self.root.after(0, lambda: self.on_tumble_cancelled(result))

        threading.Thread(target=do_cancel, daemon=True).start()

    def on_tumble_cancelled(self, result: Dict):
        if result.get('error'):
            messagebox.showerror("Error", result['error'])
        self.refresh_tumbler()

    def cleanup_tumble(self):
        def do_cleanup():
            result = self.api.cleanup_tumble()
            self.root.after(0, lambda: self.refresh_tumbler())

        threading.Thread(target=do_cleanup, daemon=True).start()

    def tab_tools(self):
        t = tk.Frame(self.nb, bg=self.C['bg'])
        self.nb.add(t, text='  \U0001f527 Tools  ')

        # Sign message
        sc = tk.Frame(t, bg=self.C['card'], padx=20, pady=15)
        sc.pack(fill='x', padx=15, pady=(12, 8))

        tk.Label(sc, text="SIGN MESSAGE", font=('Segoe UI', 10, 'bold'),
                fg=self.C['accent'], bg=self.C['card']).pack(anchor='w')

        self.sign_entry = tk.Entry(sc, font=('Segoe UI', 11), bg=self.C['input'],
                                   fg=self.C['text'], insertbackground=self.C['accent'], relief='flat')
        self.sign_entry.pack(fill='x', pady=(10, 10), ipady=8)

        tk.Button(sc, text="Sign with SE050", font=('Segoe UI', 10), bg=self.C['green'],
                 fg='#000', relief='flat', command=self.do_sign).pack(anchor='w', ipadx=12, ipady=4)

        # Pubkeys
        pc = tk.Frame(t, bg=self.C['card'], padx=20, pady=15)
        pc.pack(fill='x', padx=15, pady=(0, 8))

        hdr = tk.Frame(pc, bg=self.C['card'])
        hdr.pack(fill='x')
        tk.Label(hdr, text="EXPOSED PUBKEYS", font=('Segoe UI', 10, 'bold'),
                fg=self.C['red'], bg=self.C['card']).pack(side='left')
        tk.Button(hdr, text="\u21bb", font=('Segoe UI', 9), bg=self.C['light'],
                 fg=self.C['text'], relief='flat', command=self.refresh_pubkeys).pack(side='right')

        self.pk_txt = scrolledtext.ScrolledText(pc, font=('Courier New', 9), height=8,
                                                bg=self.C['input'], fg=self.C['accent'], relief='flat')
        self.pk_txt.pack(fill='x', pady=(10, 0))

    def do_sign(self):
        msg = self.sign_entry.get().strip()
        if not msg:
            messagebox.showerror("Error", "Enter message")
            return

        def sign():
            sig = self.api.sign_message(msg)
            self.root.after(0, lambda: self.show_sig(msg, sig))
        threading.Thread(target=sign, daemon=True).start()

    def show_sig(self, msg: str, sig: Optional[str]):
        if sig:
            win = tk.Toplevel(self.root)
            win.title("Signature")
            win.geometry("500x300")
            win.configure(bg=self.C['bg'])
            txt = scrolledtext.ScrolledText(win, font=('Courier New', 10),
                                            bg=self.C['card'], fg=self.C['text'])
            txt.pack(fill='both', expand=True, padx=12, pady=12)
            txt.insert(tk.END, f"Message:\n{msg}\n\nSignature:\n{sig}")
            txt.config(state='disabled')
        else:
            messagebox.showerror("Error", "Signing failed")

    def refresh_pubkeys(self):
        def fetch():
            pks = self.api.get_pubkeys()
            self.root.after(0, lambda: self.update_pubkeys(pks))
        threading.Thread(target=fetch, daemon=True).start()

    def update_pubkeys(self, pks: List[Dict]):
        self.pk_txt.config(state='normal')
        self.pk_txt.delete('1.0', tk.END)
        if not pks:
            self.pk_txt.insert(tk.END, "No pubkeys - waiting for mempool...")
        else:
            for pk in pks[:20]:
                self.pk_txt.insert(tk.END, f"[{pk.get('type', '?')[:6]}] {pk.get('pubkey', '')[:45]}...\n")
        self.pk_txt.config(state='disabled')

    # ===== LOGS TAB =====
    def tab_logs(self):
        t = tk.Frame(self.nb, bg=self.C['bg'])
        self.nb.add(t, text='  \U0001f4cb Logs  ')

        hdr = tk.Frame(t, bg=self.C['bg'])
        hdr.pack(fill='x', padx=15, pady=(12, 8))

        tk.Label(hdr, text="SECURITY LOGS", font=('Segoe UI', 11, 'bold'),
                fg=self.C['accent'], bg=self.C['bg']).pack(side='left')

        bf = tk.Frame(hdr, bg=self.C['bg'])
        bf.pack(side='right')

        for lt, color in [('honeypot', self.C['red']), ('access', self.C['light']), ('error', self.C['light'])]:
            tk.Button(bf, text=lt.title(), font=('Segoe UI', 9),
                     bg=color, fg='#fff' if lt == 'honeypot' else self.C['text'], relief='flat',
                     command=lambda x=lt: self.load_logs(x)).pack(side='left', padx=2)

        self.logs_txt = scrolledtext.ScrolledText(t, font=('Courier New', 9),
                                                  bg=self.C['card'], fg=self.C['text'], relief='flat')
        self.logs_txt.pack(fill='both', expand=True, padx=15, pady=(0, 12))

        self.load_logs('honeypot')

    def load_logs(self, log_type: str):
        def fetch():
            lines = self.api.get_logs(log_type)
            self.root.after(0, lambda: self.update_logs(lines, log_type))
        threading.Thread(target=fetch, daemon=True).start()

    def update_logs(self, lines: List[str], log_type: str):
        self.logs_txt.config(state='normal')
        self.logs_txt.delete('1.0', tk.END)
        self.logs_txt.insert(tk.END, f"=== {log_type.upper()} LOG ===\n\n")
        if lines:
            for line in lines:
                self.logs_txt.insert(tk.END, line + "\n")
        else:
            self.logs_txt.insert(tk.END, "(empty)")
        self.logs_txt.config(state='disabled')


# ============================================================================
#                              MAIN
# ============================================================================

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=5000)
    args = p.parse_args()

    root = tk.Tk()
    SigilDesktop(root, args.host, args.port)
    root.mainloop()

if __name__ == '__main__':
    main()
