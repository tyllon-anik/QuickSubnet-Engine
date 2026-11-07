package com.tyllon.quicksubnet;

import android.os.Bundle;
import android.text.TextUtils;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private EditText etIpAddress, etCidr;
    private Button btnCalculate;
    private TextView tvResults;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etIpAddress = findViewById(R.id.etIpAddress);
        etCidr = findViewById(R.id.etCidr);
        btnCalculate = findViewById(R.id.btnCalculate);
        tvResults = findViewById(R.id.tvResults);

        btnCalculate.setOnClickListener(v -> {
            tvResults.setText("");
            tvResults.setTextColor(0xFF8B949E);

            String ipStr = etIpAddress.getText().toString().trim();
            String cidrStr = etCidr.getText().toString().trim();

            if (TextUtils.isEmpty(ipStr) || TextUtils.isEmpty(cidrStr)) {
                showError("SYSTEM ERROR: Please enter both IP and CIDR prefix.");
                return;
            }

            if (!isValidInput(ipStr, cidrStr)) return;

            processSubnetCalculation(ipStr, cidrStr);
        });
    }

    private boolean isValidInput(String ipStr, String cidrStr) {
        int cidr;
        try {
            cidr = Integer.parseInt(cidrStr);
            if (cidr < 0 || cidr > 32) {
                showError("VALIDATION FAILED: CIDR must be between 0 and 32.");
                return false;
            }
        } catch (NumberFormatException e) {
            showError("VALIDATION FAILED: Invalid CIDR format.");
            return false;
        }

        if (!ipStr.matches("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")) {
            showError("VALIDATION FAILED: Invalid IPv4 Address format.");
            return false;
        }
        return true;
    }

    private void processSubnetCalculation(String ipStr, String cidrStr) {
        int cidr = Integer.parseInt(cidrStr);
        long ipValue = parseIpToLong(ipStr);

        long mask = (cidr == 0) ? 0 : (0xFFFFFFFFL << (32 - cidr)) & 0xFFFFFFFFL;
        long wildcard = ~mask & 0xFFFFFFFFL;

        long network = ipValue & mask;
        long broadcast = network | wildcard;

        long totalHosts = (cidr == 0) ? 4294967296L : (long) Math.pow(2, 32 - cidr);
        long usableHosts;
        String firstHost, lastHost;

        if (cidr == 32) {
            usableHosts = 1;
            firstHost = formatLongToIp(network);
            lastHost = formatLongToIp(network);
        } else if (cidr == 31) {
            usableHosts = 2;
            firstHost = formatLongToIp(network);
            lastHost = formatLongToIp(broadcast);
        } else {
            usableHosts = totalHosts - 2;
            firstHost = formatLongToIp(network + 1);
            lastHost = formatLongToIp(broadcast - 1);
        }

        // Feature 1: IP Class & Type Analyzer
        String ipClassInfo = getIpClassAndType(ipValue);
        // Feature 2: Binary Representation
        String binIp = formatLongToBinary(ipValue);
        String binMask = formatLongToBinary(mask);

        StringBuilder sb = new StringBuilder();
        sb.append("IP Address:      ").append(ipStr).append("\n");
        sb.append("IP Class:        ").append(ipClassInfo).append("\n");
        sb.append("Binary IP:       ").append(binIp).append("\n");
        sb.append("Subnet Mask:     ").append(formatLongToIp(mask)).append("\n");
        sb.append("Binary Mask:     ").append(binMask).append("\n");
        sb.append("Network ID:      ").append(formatLongToIp(network)).append("\n");
        sb.append("Broadcast ID:    ").append(formatLongToIp(broadcast)).append("\n");
        sb.append("--------------------------------\n");
        // Feature 3: Total Range explicitly shown
        sb.append("Total Range:     ").append(formatLongToIp(network)).append(" - ").append(formatLongToIp(broadcast)).append("\n");
        sb.append("Usable Range:    ").append(firstHost).append(" - ").append(lastHost).append("\n");
        sb.append("Usable Hosts:    ").append(usableHosts).append("\n");
        sb.append("Total Addresses: ").append(totalHosts).append("\n");
        sb.append("Wildcard Mask:   ").append(formatLongToIp(wildcard));

        tvResults.setText(sb.toString());
        tvResults.setTextColor(0xFF00FF66);
    }

    private void showError(String message) {
        tvResults.setText(message);
        tvResults.setTextColor(0xFFFF4444);
    }

    private long parseIpToLong(String ipAddress) {
        String[] octets = ipAddress.split("\\.");
        long result = 0;
        for (int i = 0; i < 4; i++) {
            long octet = Long.parseLong(octets[i]);
            result |= (octet << (24 - (8 * i)));
        }
        return result;
    }

    private String formatLongToIp(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                (ip & 0xFF);
    }

    // Helper Method for Binary Conversion
    private String formatLongToBinary(long value) {
        StringBuilder bin = new StringBuilder();
        for (int i = 3; i >= 0; i--) {
            long octet = (value >> (i * 8)) & 0xFF;
            String binStr = Long.toBinaryString(octet);
            bin.append(String.format("%8s", binStr).replace(' ', '0'));
            if (i > 0) bin.append(".");
        }
        return bin.toString();
    }

    // Helper Method for IP Class & Type Detection
    private String getIpClassAndType(long ipValue) {
        long firstOctet = (ipValue >> 24) & 0xFF;
        long secondOctet = (ipValue >> 16) & 0xFF;

        String ipClass = "";
        String ipType = "Public";

        if (firstOctet >= 1 && firstOctet <= 126) {
            ipClass = "Class A";
            if (firstOctet == 10) ipType = "Private";
        } else if (firstOctet == 127) {
            ipClass = "Loopback";
            ipType = "Reserved";
        } else if (firstOctet >= 128 && firstOctet <= 191) {
            ipClass = "Class B";
            if (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31) ipType = "Private";
            else if (firstOctet == 169 && secondOctet == 254) ipType = "APIPA";
        } else if (firstOctet >= 192 && firstOctet <= 223) {
            ipClass = "Class C";
            if (firstOctet == 192 && secondOctet == 168) ipType = "Private";
        } else if (firstOctet >= 224 && firstOctet <= 239) {
            ipClass = "Class D (Multicast)";
            ipType = "Reserved";
        } else if (firstOctet >= 240 && firstOctet <= 255) {
            ipClass = "Class E (Experimental)";
            ipType = "Reserved";
        } else {
            ipClass = "Unknown";
        }

        return ipClass + " (" + ipType + ")";
    }
}