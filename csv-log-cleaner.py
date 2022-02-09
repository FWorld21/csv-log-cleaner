#!/usr/bin/env python3
import os.path
import csv
from optparse import OptionParser
from datetime import datetime

parser = OptionParser()
parser.add_option("-f", "--file", dest="file",
                  help="Give file location to convert it to readable format", metavar="FILE")
parser.add_option("-c", "--columns", dest="columns",
                  help="You can add columns using comma like separator", metavar="COLUMNS")
parser.add_option("-r", "--risk", dest="risk",
                  help="You can add Security Risk Level names, using comma like separator")
parser.add_option("-m", "--mode", dest="mode",
                  help="Which output do you like? Available options: html/csv", metavar="MODE")
(options, args) = parser.parse_args()


class LogToHtml:
    def __init__(self):
        self.available_modes = ["html", "csv"]
        self.file_location = options.file
        self.mode = options.mode

        self.risk_levels = ["HIGH", "CRITICAL"]
        if options.risk is not None:
            self.risk_levels += options.risk.split(",")

        self.columns = ["Component name", "Component version name", "Vulnerability id", "Description", "URL"]
        if options.columns is not None:
            self.columns += options.columns.split(",")

        # Content will be taken from file
        self.headers = []
        self.rows = []

        self.output_filename = f"{datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}_clean_logs"
        self.logs_folder = "./logs"

    def check_for_errors(self):
        """This method show error while using script and creating default logs folder"""
        if not os.path.exists("./logs"):
            os.mkdir("logs")
        if self.mode is None:
            print(f"[!] Output from {__file__}: \n[!] Please select mode. --help for more information")
            return False
        if self.file_location is not None and not os.path.exists(self.file_location):
            print(f"[!] Output from {__file__}: \n[!] 404 error. File {self.file_location} not found")
            return False
        if self.file_location is None:
            print(f"[!] Output from {__file__}: \n[!] File not specified")
            return False
        if self.mode not in self.available_modes:
            print(f"[!] Output from {__file__}: \n[!] Invalid mode specified")
            return False
        return True

    def risk_filter(self):
        """This method filtering content by risk level"""
        with open(f"{self.file_location}", "r") as file:
            csvreader = csv.reader(file)
            self.headers = next(csvreader)
            for row in csvreader:
                for risk_level in self.risk_levels:
                    if risk_level in row:
                        self.rows.append(row)

    def columns_content_filter(self):
        """This method filtering content by specified columns"""
        for header in self.headers[:]:
            if header not in self.columns[:]:
                for row in self.rows:
                    del row[self.headers.index(header)]
                self.headers.remove(header)

    def add_to_logs(self, content, filetype="html"):
        """For beautify code only"""
        with open(os.path.join("logs", self.output_filename + f".{filetype}"), "r") as file_r:
            data = file_r.read()
        with open(os.path.join("logs", self.output_filename + f".{filetype}"), "w") as file_w:
            file_w.write(data)
            file_w.write(content)

    def html_output(self):
        """This method put clean output into simple HTML file"""
        with open(f"./logs/{self.output_filename}.html", "w") as clean_logs_file_w:
            clean_logs_file_w.write("""
                <!DOCTYPE html>
                <html lang="ru" class="scroll-smooth">
                  <head>
                    <meta charset="UTF-8" />
                    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
                    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                  </head>
                  <body>
                    <ol>
            """)
        for row in self.rows:
            self.add_to_logs(content="<li>")
            for value in row:
                if value[0:8] == "https://":
                    self.add_to_logs(content=f"{self.headers[row.index(value)]}: <a href={value}>{value}</a><br>")
                else:
                    self.add_to_logs(content=f"{self.headers[row.index(value)]}: {value}<br>")

            self.add_to_logs(content="</li><br><br><br>")
        self.add_to_logs(content="""
                    </ol>
                  </body>
                </html>
            """)
        print(f"[+] Output from {__file__}: \n[+] Logs successfully saved in "
              f"{os.path.join(os.getcwd(), f'logs/{self.output_filename}.html')}")

    def csv_output(self):
        """This method put clean output into simple CSV file"""
        with open(f"logs/{self.output_filename}.csv", 'w', newline="") as file:
            csvwriter = csv.writer(file)
            csvwriter.writerow(self.headers)
            csvwriter.writerows(self.rows)
        print(f"[+] Output from {__file__}: \n[+] Logs successfully saved in "
              f"{os.path.join(os.getcwd(), f'logs/{self.output_filename}.csv')}")

    def output(self):
        if self.mode == self.available_modes[0]:  # HTML
            self.html_output()
        elif self.mode == self.available_modes[1]:  # CSV
            self.csv_output()

    def start_parse(self):
        if self.check_for_errors():
            self.risk_filter()
            self.columns_content_filter()
            self.output()


html_builder = LogToHtml()
html_builder.start_parse()
