#!/bin/bash
clear
echo ""
echo -e "\e[92m"
echo "  ██████╗██╗   ██╗██████╗ ███████╗██████╗ "
echo " ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗"
echo " ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝"
echo " ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗"
echo " ╚██████╗   ██║   ██████╔╝███████╗██║  ██║"
echo "  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝"
echo -e "\e[0m"
echo -e "\e[96m        ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗\e[0m"
echo -e "\e[96m        ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║\e[0m"
echo -e "\e[96m        ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║\e[0m"
echo -e "\e[96m        ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║\e[0m"
echo -e "\e[96m        ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗\e[0m"
echo -e "\e[96m        ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝\e[0m"
echo ""
echo -e "\e[93m        AI-Powered Cybersecurity Threat Detection Platform\e[0m"
echo -e "\e[90m        =================================================\e[0m"
echo ""
sleep 2
echo -e "\e[97m [1/3] Installing dependencies...\e[0m"
pip install -r requirements.txt
echo -e "\e[92m  ✅ Done!\e[0m"
echo ""
echo -e "\e[97m [2/3] Checking database...\e[0m"
psql -U postgres -c "CREATE DATABASE cybersentinel;" 2>/dev/null
echo -e "\e[92m  ✅ Done!\e[0m"
echo ""
echo -e "\e[97m [3/3] Launching CyberSentinel...\e[0m"
echo ""
python main.py
