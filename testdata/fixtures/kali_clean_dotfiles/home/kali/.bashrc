# ~/.bashrc: executed by bash(1) for non-login shells.
[ -z "$PS1" ] && return
shopt -s checkwinsize

if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
    color_prompt=yes
fi
