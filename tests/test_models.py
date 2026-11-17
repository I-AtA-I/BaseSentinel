
from basesentinel import create_app, db
from basesentinel.models import Asset, AssetAddress, AssetInterface


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def test_asset_inventory_relationships():
    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()

        try:
            asset = Asset(
                display_name="Test Workstation",
                hostname="test-pc",
                asset_type="workstation",
            )

            interface = AssetInterface(
                interface_key="ethernet-1",
                interface_name="Ethernet",
                interface_type="ethernet",
                mac_address="02:00:00:00:00:01",
            )

            address = AssetAddress(
                ip_address="192.0.2.10",
                prefix_length=24,
                network_scope="test-network",
            )

            interface.addresses.append(address)
            asset.interfaces.append(interface)

            db.session.add(asset)
            db.session.commit()

            assert Asset.query.count() == 1
            assert AssetInterface.query.count() == 1
            assert AssetAddress.query.count() == 1

            assert interface.asset_id == asset.id
            assert address.interface_id == interface.id

        finally:
            db.session.rollback()
            db.session.remove()
            db.drop_all()


def test_inventory_tables_registered():
    app = create_app(TestConfig)

    with app.app_context():
        expected_tables = {
            "assets",
            "asset_interfaces",
            "asset_addresses",
        }

        assert expected_tables.issubset(db.metadata.tables.keys())
