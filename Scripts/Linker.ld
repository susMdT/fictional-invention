
SECTIONS
{
	.text :
	{
		*( .text$A )
		*( .text$B )
		*( .text$C )
		*( .text$D )
		*( .text$E )
		*( .rdata* )
		*( .text$F )
		*( .text$END )
		. += 4096;
		*( .text$INSTANCE )
	} = 0x6969
}