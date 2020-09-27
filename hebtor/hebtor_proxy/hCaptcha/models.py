import datetime

from django.db import models
from django.utils import timezone


class SessionInfo(models.Model):
    session_id = models.CharField(max_length=4092)
    hidden_address = models.CharField(max_length=512)
    valid_from = models.IntegerField()
    valid_until = models.IntegerField()

    def __str__(self):
        return "%s" % [self.session_id, self.hidden_address, self.valid_from, self.valid_until]
