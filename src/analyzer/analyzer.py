# part 2
# app/AnalyzerService.py
from .Analyzer import Analyzer
from .Reporter import Reporter

class AnalyzerService:
    def run_scan(self, opt):
        analyzer = Analyzer()
        return analyzer.analyzePath(opt.path, opt)

    def format_report_text(self, res, opt):
        reporter = Reporter()
        return reporter.toText(res, opt)