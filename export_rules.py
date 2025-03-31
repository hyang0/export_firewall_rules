import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import winreg
import os
import ipaddress
from pprint import pprint
import sys


class Debug:
    """
    调试信息控制类，包装pprint方法进行格式化输出

    类属性:
        is_debug (bool): 控制调试模式开关，True时输出调试信息

    方法:
        print(*args, **kwargs): 当is_debug为True时，调用pprint.pprint输出内容
    """
    is_debug = False

    @classmethod
    def print(cls, *args, **kwargs):
        """
        调试信息打印方法，当is_debug=True时实际执行打印

        参数:
            *args: 任意位置参数，传递给pprint.pprint
            **kwargs: 任意关键字参数，传递给pprint.pprint
        """
        if cls.is_debug:
            pprint(*args, **kwargs)
            sys.stdout.flush()



class FirewallExporterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("防火墙规则导出工具")
        self.root.geometry("800x600")
        
        self.create_widgets()
        self.setup_layout()
    
    def create_widgets(self):
        # 控制按钮区域
        self.control_frame = ttk.Frame(self.root)
        self.export_btn = ttk.Button(self.control_frame, text="导出规则", command=self.export_rules)
        self.save_btn = ttk.Button(self.control_frame, text="保存结果", command=self.save_results, state=tk.DISABLED)
        self.copy_btn = ttk.Button(self.control_frame, text="复制到剪贴板", command=self.copy_to_clipboard, state=tk.DISABLED)
        
        # 结果显示区域
        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=('Consolas', 10))
        self.result_text.configure(state='disabled')
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
    
    def setup_layout(self):
        # 按钮布局
        self.control_frame.pack(pady=10, fill=tk.X)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        self.save_btn.pack(side=tk.LEFT, padx=5)
        self.copy_btn.pack(side=tk.LEFT, padx=5)
        
        # 结果显示区域
        self.result_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        
        # 状态栏
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def export_rules(self):
        """执行导出操作"""
        try:
            rules = self.parse_firewall_rules()
            self.show_results(rules)
            self.status_var.set(f"成功导出 {len(rules)} 条防火墙规则")
            self.save_btn.config(state=tk.NORMAL)
            self.copy_btn.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {str(e)}")
            self.status_var.set("导出失败")
    
    def show_results(self, rules):
        """在文本框中显示结果"""
        self.result_text.configure(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "\n\n".join(rules))
        self.result_text.configure(state='disabled')
    
    def save_results(self):
        """保存结果到文件"""
        content = self.result_text.get(1.0, tk.END)
        if not content.strip():
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".bat",
            filetypes=[("批处理文件", "*.bat"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("@echo off\n")
                    f.write(":: 自动生成的防火墙规则脚本\n\n")
                    f.write(content)
                messagebox.showinfo("保存成功", f"文件已保存至：{file_path}")
            except Exception as e:
                messagebox.showerror("保存失败", str(e))
    
    def copy_to_clipboard(self):
        """复制内容到剪贴板"""
        content = self.result_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status_var.set("内容已复制到剪贴板")
    
    # 以下是原始脚本的功能函数（稍作修改）-------------------------------------
    
    @staticmethod
    def expand_env_vars(path):
        return os.path.expandvars(path)
    
    def parse_firewall_rules(self):
        rules = []
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
            )
        except WindowsError as e:
            raise Exception(f"无法访问防火墙规则注册表项: {str(e)}")
        
        i = 0
        while True:
            try:
                value_name, value_data, _ = winreg.EnumValue(key, i)
                i += 1
                rules.append(self.parse_rule(value_data, value_name))
            except OSError:
                break
        
        winreg.CloseKey(key)
        return rules
    
    @staticmethod
    def convert_subnet_mask(cidr_str):
        if '/' not in cidr_str:
            return cidr_str
        ip_str, mask_str = cidr_str.split('/', 1)
        try:
            if '.' in mask_str:
                mask = ipaddress.IPv4Address(mask_str)
                prefix_len = bin(int(mask)).count('1')
                return f"{ip_str}/{prefix_len}"
            return cidr_str
        except:
            return cidr_str
    
    def parse_ip_specials(self, ip_str):
        ip_str = ip_str.strip()
        if '-' in ip_str:
            return ip_str
        if '/' in ip_str and '.' in ip_str.split('/')[1]:
            return self.convert_subnet_mask(ip_str)
        return ip_str
    
    def parse_rule(self, rule_data, value_name):
        params = {}
        ra4_list = []
        la4_list = []
        fields = rule_data.split('|')
        Debug.print(fields)
        
        for field in fields:
            if '=' not in field:
                continue
            key, val = field.split('=', 1)
            key_lower = key.lower()
            
            if key == 'RA4':
                ra4_list.append(self.parse_ip_specials(val))
            elif key == 'LA4':
                la4_list.append(self.parse_ip_specials(val))
            else:
                params[key_lower] = val
        
        cmd_params = {
            'name': f'"{params.get("name", value_name)}"',
            'dir': 'in' if params.get('dir', '').lower() == 'in' else 'out',
            'action': params.get('action', 'allow').lower(),
            'enable': 'yes' if params.get('active', 'false').lower() == 'true' else 'no',
            'profile': params.get('profile', 'any').lower().replace('domain,private,public', 'all'),
        }
        
        protocol_map = {'6': 'tcp', '17': 'udp', '1': 'icmpv4', '58': 'icmpv6'}
        protocol = params.get('protocol', 'any')
        cmd_params['protocol'] = protocol_map.get(protocol, protocol.lower())
        
        if local_ports := params.get('lport'):
            cmd_params['localport'] = local_ports.replace(' ', '')
            Debug.print(cmd_params)
        if remote_ports := params.get('rport'):
            cmd_params['remoteport'] = remote_ports.replace(' ', '')
        
        if app_path := params.get('app'):
            expanded_path = self.expand_env_vars(app_path)
            if os.path.exists(expanded_path):
                cmd_params['program'] = f'"{expanded_path}"'
        
        def format_ips(ip_list):
            valid_ips = []
            for ip in ip_list:
                if ip.lower() == 'any':
                    continue
                try:
                    if '-' in ip:
                        start_ip, end_ip = ip.split('-')
                        ipaddress.IPv4Address(start_ip)
                        ipaddress.IPv4Address(end_ip)
                        valid_ips.append(ip)
                    elif '/' in ip:
                        ipaddress.IPv4Network(ip, strict=False)
                        valid_ips.append(ip)
                    else:
                        ipaddress.IPv4Address(ip)
                        valid_ips.append(ip)
                except:
                    continue
            return ','.join(valid_ips) if valid_ips else None
        
        if ra4_ips := format_ips(ra4_list):
            cmd_params['remoteip'] = ra4_ips
        if la4_ips := format_ips(la4_list):
            cmd_params['localip'] = la4_ips
        
        cmd = 'netsh advfirewall firewall add rule'
        for key, val in cmd_params.items():
            if val and val not in ('any', 'all'):
                cmd += f' {key}={val}'
        return cmd

if __name__ == '__main__':
    Debug.is_debug = False
    root = tk.Tk()
    app = FirewallExporterApp(root)
    root.mainloop()
