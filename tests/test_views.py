from unittest import mock
from unittest.mock import patch

import pytz
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from drf_expiring_token.models import ExpiringToken


class ExpiringTokenAuthenticationTestCase(TestCase):
    """Test the authentication class directly."""

    def setUp(self):
        """Create a user and associated token."""
        self.username = 'test_username'
        self.email = 'test@g.com'
        self.password = 'test_password'
        self.user = User.objects.create_user(
            username=self.username,
            email=self.email,
            password=self.password
        )

        self.key = 'jhfbgkjasnlkfmlkn'
        self.token = ExpiringToken.objects.create(
            user=self.user,
            key=self.key
        )
        self.client = APIClient()

    def test_create_token(self):
        user = User.objects.create_user(
            username="test",
            email="",
            password="abcd1234"
        )
        data = {'username': 'test', 'password': 'abcd1234'}
        resp = self.client.post(reverse('obtain-token'), data)

        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_obtain_token_no_credentials(self):
        resp = self.client.post(reverse('obtain-token'))
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_obtain_token_bad_credentials(self):
        data = {'username': 'test_username', 'password': 'blblb'}
        resp = self.client.post(reverse('obtain-token'), data)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(resp.data['detail'], 'Invalid Credentials')

    def test_obtain_token_good_credentials(self):
        data = {'username': 'test_username', 'password': 'test_password'}
        resp = self.client.post(reverse('obtain-token'), data)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(self.key, resp.data['token'])

    def test_obtain_token_inactive_user(self):
        username = 'test_username_non_active'
        email = 'test@gg.com'
        password = 'test_password'
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )
        user.is_active = False
        user.save()

        data = {'username': 'test_username_non_active', 'password': 'test_password'}
        resp = self.client.post(reverse('obtain-token'), data)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(resp.data['detail'], 'Invalid Credentials')

    def test_replace_expired_token(self):
        with patch('django.utils.timezone.now',
                   mock.MagicMock(return_value=timezone.datetime(2020, 8, 17, 8, 1, 0, tzinfo=pytz.UTC))):
            self.token.delete()
            token = ExpiringToken.objects.create(user=self.user)
            key_1 = token.key

            data = {'username': 'test_username', 'password': 'test_password'}

        with patch('django.utils.timezone.now',
                   mock.MagicMock(return_value=timezone.datetime(2020, 8, 17, 8, 1, 40, tzinfo=pytz.UTC))):
            resp = self.client.post(reverse('obtain-token'), data)

            self.assertEqual(resp.status_code, status.HTTP_200_OK)

            token = ExpiringToken.objects.first()
            key_2 = token.key
            self.assertEqual(token.user, self.user)
            self.assertEqual(resp.data['token'], token.key)
            self.assertTrue(key_1 != key_2)

    def create_datetime(self, year, month, day, hour, minutes=0, seconds=0, microseconds=0, tzinfo=pytz.UTC):
        return

    def test_revoke_no_token(self):
        resp = self.client.post(reverse('revoke-token'))
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(resp.data['detail'],
                         'Authentication credentials were not provided.')

    def test_revoke_valid_token(self):
        user = User.objects.create_user(username='test_revoke_valid_token')
        with patch('django.utils.timezone.now',
                   mock.MagicMock(return_value=timezone.datetime(2020, 8, 17, 8, 1, 0, tzinfo=pytz.UTC))):
            token = ExpiringToken.objects.create(user=user)

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        now = timezone.datetime(2020, 8, 17, 8, 1, 5, tzinfo=pytz.UTC)
        with patch('django.utils.timezone.now', mock.MagicMock(return_value=now)):
            resp = self.client.post(reverse('revoke-token'))

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        token.refresh_from_db()
        self.assertEqual(token.expires, now)

    def test_revoke_expired_token(self):
        user = User.objects.create_user(username='test_revoke_expired_token')
        with patch('django.utils.timezone.now',
                   mock.MagicMock(return_value=timezone.datetime(2020, 8, 17, 8, 1, 0, tzinfo=pytz.UTC))):
            token = ExpiringToken.objects.create(user=user)

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        with patch('django.utils.timezone.now',
                   mock.MagicMock(return_value=timezone.datetime(2020, 8, 17, 8, 1, 15, tzinfo=pytz.UTC))):
            resp = self.client.post(reverse('revoke-token'))

        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(resp.data['detail'], 'The Token is expired')
