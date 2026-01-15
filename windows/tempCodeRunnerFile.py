                # Format display message with attack type if malicious
                if is_malicious:
                    msg = f"{timestamp} [⚠️ ALERT - {attack_type}] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
                    self.alerts_log.append(log_entry)
                    self.save_to_log_file(log_entry)  # Automatically save to log file
                    self.alert_textbox.insert("1.0", msg, "red_alert")
                else:
                    msg = f"{timestamp} [NORMAL] {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
                    self.alert_textbox.insert("1.0", msg)