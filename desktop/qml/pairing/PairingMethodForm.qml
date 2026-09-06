import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import PCBioUnlock
import 'qrc:/ui/base'

StepForm {
    description: QI18n.Get('pairing_form_method_desc')
    Rectangle {
        Layout.fillWidth: true
        Layout.fillHeight: true
        color: window.color
        ColumnLayout {
            anchors.verticalCenter: parent.verticalCenter
            spacing: 25
            ButtonGroup {
                id: methodRadioGroup
                onClicked: function(button) {
                    let data = PairingForm.GetData();
                    data.pairingMethod = button.methodStr;
                    PairingForm.SetData(data);
                }
            }
            ColumnLayout {
                visible: PairingForm.GetData().pairingMethodType === 'AUTO'
                RadioButton {
                    ButtonGroup.group: methodRadioGroup
                    property string methodStr: 'UDP'
                    text: QI18n.Get('pairing_method_udp_select')
                    checked: PairingForm.GetData().pairingMethod === methodStr
                }
                Label {
                    Layout.preferredWidth: 500
                    Layout.leftMargin: 40
                    text: QI18n.Get('pairing_method_udp_desc')
                    wrapMode: Label.WordWrap
                }
            }
            ColumnLayout {
                visible: PairingForm.GetData().pairingMethodType === 'AUTO'
                RadioButton {
                    ButtonGroup.group: methodRadioGroup
                    property string methodStr: 'TCP'
                    text: QI18n.Get('pairing_method_tcp_select')
                    checked: PairingForm.GetData().pairingMethod === methodStr
                }
                Label {
                    Layout.preferredWidth: 500
                    Layout.leftMargin: 40
                    text: QI18n.Get('pairing_method_tcp_desc')
                    wrapMode: Label.WordWrap
                }
            }
            ColumnLayout {
                visible: PairingForm.GetData().pairingMethodType === 'AUTO'
                enabled: PairingForm.HasBluetooth()
                RadioButton {
                    ButtonGroup.group: methodRadioGroup
                    property string methodStr: 'BLUETOOTH'
                    text: QI18n.Get('pairing_method_bt_select')
                    checked: PairingForm.GetData().pairingMethod === methodStr
                }
                Label {
                    Layout.preferredWidth: 500
                    Layout.leftMargin: 40
                    text: QI18n.Get('pairing_method_bt_desc')
                    wrapMode: Label.WordWrap
                }
            }

            // Bluetooth LE. Separate from the BLUETOOTH option above because
            // that one is Classic RFCOMM, which an iPhone cannot use at all -
            // iOS restricts Classic to MFi hardware, so a Classic inquiry
            // never lists an iPhone. BLE is the only Bluetooth route to iOS.
            //
            // No device-select step here: the phone scans for this PC's GATT
            // advertisement rather than the PC scanning for phones, so the
            // flow goes straight to the QR code like the Wi-Fi methods.
            ColumnLayout {
                visible: PairingForm.GetData().pairingMethodType === 'AUTO'
                enabled: PairingForm.HasBluetooth()
                RadioButton {
                    ButtonGroup.group: methodRadioGroup
                    property string methodStr: 'BLE'
                    text: QI18n.Get('pairing_method_ble_select')
                    checked: PairingForm.GetData().pairingMethod === methodStr
                }
                Label {
                    Layout.preferredWidth: 500
                    Layout.leftMargin: 40
                    text: QI18n.Get('pairing_method_ble_desc')
                    wrapMode: Label.WordWrap
                }
            }

            ColumnLayout {
                visible: PairingForm.GetData().pairingMethodType === 'MANUAL'
                RadioButton {
                    ButtonGroup.group: methodRadioGroup
                    property string methodStr: 'MANUAL_UDP'
                    text: QI18n.Get('pairing_method_manual_udp_select')
                    checked: PairingForm.GetData().pairingMethod === methodStr
                }
                Label {
                    Layout.preferredWidth: 500
                    Layout.leftMargin: 40
                    text: QI18n.Get('pairing_method_manual_udp_desc')
                    wrapMode: Label.WordWrap
                }
            }
        }
    }
}
