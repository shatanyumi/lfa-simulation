$TTL    604800
@       IN      SOA     ns.lfa.com. admin.lfa.com. (
                            2025092601 ; Serial
                            604800     ; Refresh
                            86400      ; Retry
                            2419200    ; Expire
                            604800 )   ; Negative Cache TTL

; Name server
@       IN      NS      ns.lfa.com.
ns      IN      A       10.0.100.2

; IDC Group 1
idcg1h1     IN      A       10.0.10.2
idcg1h2     IN      A       10.0.10.3
idcg1h3     IN      A       10.0.10.4
idcg1h4     IN      A       10.0.10.5
idcg1h5     IN      A       10.0.10.6
idcg1h6     IN      A       10.0.10.7
idcg1h7     IN      A       10.0.10.8
idcg1h8     IN      A       10.0.10.9
idcg1h9     IN      A       10.0.10.10
idcg1h10    IN      A       10.0.10.11
idcg1h11    IN      A       10.0.10.12
idcg1h12    IN      A       10.0.10.13

; IDC Group 2
idcg2h1     IN      A       10.0.20.2
idcg2h2     IN      A       10.0.20.3
idcg2h3     IN      A       10.0.20.4
idcg2h4     IN      A       10.0.20.5
idcg2h5     IN      A       10.0.20.6
idcg2h6     IN      A       10.0.20.7
idcg2h7     IN      A       10.0.20.8
idcg2h8     IN      A       10.0.20.9
idcg2h9     IN      A       10.0.20.10
idcg2h10    IN      A       10.0.20.11
idcg2h11    IN      A       10.0.20.12
idcg2h12    IN      A       10.0.20.13

; IDC Group 3
idcg3h1     IN      A       10.0.30.2
idcg3h2     IN      A       10.0.30.3
idcg3h3     IN      A       10.0.30.4
idcg3h4     IN      A       10.0.30.5
idcg3h5     IN      A       10.0.30.6
idcg3h6     IN      A       10.0.30.7
idcg3h7     IN      A       10.0.30.8
idcg3h8     IN      A       10.0.30.9
idcg3h9     IN      A       10.0.30.10
idcg3h10    IN      A       10.0.30.11
idcg3h11    IN      A       10.0.30.12
idcg3h12    IN      A       10.0.30.13

; IDC Group 4
idcg4h1     IN      A       10.0.40.2
idcg4h2     IN      A       10.0.40.3
idcg4h3     IN      A       10.0.40.4
idcg4h4     IN      A       10.0.40.5
idcg4h5     IN      A       10.0.40.6
idcg4h6     IN      A       10.0.40.7
idcg4h7     IN      A       10.0.40.8
idcg4h8     IN      A       10.0.40.9
idcg4h9     IN      A       10.0.40.10
idcg4h10    IN      A       10.0.40.11
idcg4h11    IN      A       10.0.40.12
idcg4h12    IN      A       10.0.40.13

; IDC Group 5
idcg5h1     IN      A       10.0.50.2
idcg5h2     IN      A       10.0.50.3
idcg5h3     IN      A       10.0.50.4
idcg5h4     IN      A       10.0.50.5
idcg5h5     IN      A       10.0.50.6
idcg5h6     IN      A       10.0.50.7
idcg5h7     IN      A       10.0.50.8
idcg5h8     IN      A       10.0.50.9
idcg5h9     IN      A       10.0.50.10
idcg5h10    IN      A       10.0.50.11
idcg5h11    IN      A       10.0.50.12
idcg5h12    IN      A       10.0.50.13