import datetime

from django.db import models
from django.utils import timezone


class ProxyInfo(models.Model):
    proxy_id = models.CharField(max_length=4096)
    verification_key = models.CharField(max_length=1024)
    site_key = models.CharField(max_length=1024)
    current_reputation = models.FloatField()
    is_advertising = models.BooleanField()
    hidden_address = models.CharField(max_length=512)
    avail_num = models.IntegerField()

    def __str__(self):
        return "%s" % [self.proxy_id, self.current_reputation, self.is_advertising, self.hidden_address, self.avail_num]


class EarlyAssignmentInfo(models.Model):
    session_id = models.CharField(max_length=4096)
    proxy_id = models.CharField(max_length=4096)
    verification_key = models.CharField(max_length=1024)
    timestamp = models.FloatField()


class AssignmentInfo(models.Model):
    session_id = models.CharField(max_length=4096)
    hidden_address = models.CharField(max_length=512)
    is_paid = models.BooleanField()

    def __str__(self):
        return "%s" % [self.session_id, self.hidden_address, self.is_paid]


class ReputationTags(models.Model):
    session_id = models.CharField(max_length=4096)
    tag_id = models.IntegerField()
    vote = models.IntegerField()
    timestamp = models.IntegerField()

    def __str__(self):
        return "%s" % [self.session_id, self.tag_id, self.vote, self.timestamp]


class Reputation(models.Model):
    proxy_id = models.CharField(max_length=4096)
    votes = models.FloatField()
    timestamp = models.IntegerField()

    def __str__(self):
        return "%s" % [self.proxy_id, self.votes, self.timestamp]


class ExpireTask(models.Model):
    expire_timestamp = models.IntegerField()
    callback_info = models.CharField(max_length=4096)

    def __str__(self):
        return "%s" % [self.expire_timestamp, self.callback_info]


class TicketKeys(models.Model):
    key_pem = models.CharField(max_length=8192)
    expire = models.FloatField()
    key_type = models.CharField(max_length=32)  # sign, verify


class UsedTickets(models.Model):
    ticket_serial = models.CharField(max_length=4096)
    insert_time = models.FloatField()
