"""
Tests for opt-in TLS support on the MQTT broker connection.

The MQTT client library (aiomqtt) is an EXTERNAL resource and is mocked here so the
tests assert *how* it is configured (the TLS context we hand it) without opening a
real socket. Internal api modules are exercised for real.

Run with: pytest test/test_mqtt_tls.py -v
"""
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from config import BrokerSettings
from utils.mqtt_manager import MQTTManager


def _make_mock_client():
    """Build a mock aiomqtt.Client usable as an async context manager."""
    client = MagicMock(name="aiomqtt.Client")
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.subscribe = AsyncMock()
    return client


async def _enter_get_client(manager: MQTTManager):
    """Drive MQTTManager._get_client through one enter/exit and return the mock Client class."""
    with patch("utils.mqtt_manager.aiomqtt.Client") as mock_client_cls:
        mock_client_cls.return_value = _make_mock_client()
        async with manager._get_client():
            pass
        return mock_client_cls


class TestBrokerTLSSettings:
    """BrokerSettings TLS fields: default OFF and env-driven."""

    def test_tls_defaults_off(self):
        broker = BrokerSettings()
        assert broker.ssl is False
        assert broker.ca_cert is None

    def test_tls_enabled_via_environment(self, monkeypatch):
        monkeypatch.setenv("BROKER_SSL", "true")
        monkeypatch.setenv("BROKER_CA_CERT", "/etc/ssl/certs/broker-ca.pem")
        broker = BrokerSettings()
        assert broker.ssl is True
        assert broker.ca_cert == "/etc/ssl/certs/broker-ca.pem"


class TestMQTTManagerTLSWiring:
    """MQTTManager wires an SSLContext into aiomqtt only when TLS is enabled."""

    @pytest.mark.asyncio
    async def test_tls_off_passes_no_context(self):
        manager = MQTTManager(host="broker", port=1883, username="u", password="p")
        mock_client_cls = await _enter_get_client(manager)

        _, kwargs = mock_client_cls.call_args
        assert kwargs["tls_context"] is None

    @pytest.mark.asyncio
    async def test_tls_on_passes_ssl_context(self):
        manager = MQTTManager(host="broker", port=8883, username="u", password="p", use_tls=True)
        mock_client_cls = await _enter_get_client(manager)

        _, kwargs = mock_client_cls.call_args
        assert isinstance(kwargs["tls_context"], ssl.SSLContext)
        assert kwargs["port"] == 8883

    @pytest.mark.asyncio
    async def test_tls_on_without_credentials_passes_ssl_context(self):
        manager = MQTTManager(host="broker", port=8883, username="", password="", use_tls=True)
        mock_client_cls = await _enter_get_client(manager)

        _, kwargs = mock_client_cls.call_args
        assert isinstance(kwargs["tls_context"], ssl.SSLContext)
        assert "username" not in kwargs

    @pytest.mark.asyncio
    async def test_ca_cert_loaded_into_context(self):
        manager = MQTTManager(
            host="broker", port=8883, username="u", password="p", use_tls=True, ca_cert="/path/ca.pem"
        )
        with patch("utils.mqtt_manager.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value = MagicMock(spec=ssl.SSLContext)
            manager._build_tls_context()
            _, kwargs = mock_ctx.call_args
            assert kwargs["cafile"] == "/path/ca.pem"
            assert kwargs["purpose"] == ssl.Purpose.SERVER_AUTH

    @pytest.mark.asyncio
    async def test_no_ca_cert_uses_system_trust_store(self):
        manager = MQTTManager(host="broker", port=8883, username="u", password="p", use_tls=True)
        with patch("utils.mqtt_manager.ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value = MagicMock(spec=ssl.SSLContext)
            manager._build_tls_context()
            _, kwargs = mock_ctx.call_args
            # cafile=None => Python loads the system default trust store.
            assert kwargs["cafile"] is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
