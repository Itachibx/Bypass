from prettytable import PrettyTable

from prettytable import PrettyTable

def table_get_result_summary(statuses, wb_result=None):
    table = PrettyTable()
    table.field_names = ["Loại", "Số lượng"]

    table.add_row(["BYPASSED", statuses.get("BYPASSED", 0)])
    table.add_row(["BLOCKED", statuses.get("BLOCKED", 0)])
    table.add_row(["PASSED", statuses.get("PASSED", 0)])
    table.add_row(["FALSED", statuses.get("FALSED", 0)])

    # Nếu có wb_result thì in ra thông tin
    if wb_result:
        table.add_row(["WB_RESULT", wb_result])

    total_dangerous = statuses.get("BYPASSED", 0) + statuses.get("BLOCKED", 0)
    ratio = (statuses.get("BYPASSED", 0) / total_dangerous) * 100 if total_dangerous > 0 else 0

    print(table)
    print(f"Tỷ lệ bypass thành công: {ratio:.2f}%")