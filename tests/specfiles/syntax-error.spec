# %%if without else causes a syntax error.  But the statements before the syntax
# error _are_ parsed and reflected.
ExclusiveArch: aarch64
%if
Version: 10
%else
Version: 11
%endif
# this is ignored
ExcludeArch: aarch64
