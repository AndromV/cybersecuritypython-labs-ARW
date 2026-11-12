DOMAIN_TITLE = "Облік часу опрацювання повідомлень"
DOMAIN_DESCRIPTION = (
    "Сервіс обліку тривалості перевірки повідомлень про події безпеки. "
    "Категорія визначає джерело повідомлення, value — тривалість у хвилинах, "
    "status — стан перевірки вимірювання."
)
UNIT = "minutes"
THRESHOLD = 15.0

ALLOWED_STATUSES = ("new", "in_progress", "done")
MIN_VALUE = 0.0
MAX_VALUE = 1.7976931348623157e308
