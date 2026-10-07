## Patch Description

Fix a buffer overflow bug in a recent check-in, reported by unsolicted
email from OpenAI/Codex.

FossilOrigin-Name: be891a137af15897691250324e4d3d9c96f0c5fb414bca27d0c3bfdd3012a8a2

## Buggy Code

```c
// Function: sqlite3_str_vappendf in src/printf.c
void sqlite3_str_vappendf(
  sqlite3_str *pAccum,       /* Accumulate results here */
  const char *fmt,           /* Format string */
  va_list ap                 /* arguments */
){
  int c;                     /* Next character in the format string */
  char *bufpt;               /* Pointer to the conversion buffer */
  int precision;             /* Precision of the current field */
  int length;                /* Length of the field */
  int idx;                   /* A general purpose loop counter */
  int width;                 /* Width of the current field */
  etByte flag_leftjustify;   /* True if "-" flag is present */
  etByte flag_prefix;        /* '+' or ' ' or 0 for prefix */
  etByte flag_alternateform; /* True if "#" flag is present */
  etByte flag_altform2;      /* True if "!" flag is present */
  etByte flag_zeropad;       /* True if field width constant starts with zero */
  etByte flag_long;          /* 1 for the "l" flag, 2 for "ll", 0 by default */
  etByte done;               /* Loop termination flag */
  etByte cThousand;          /* Thousands separator for %d and %u */
  etByte xtype = etINVALID;  /* Conversion paradigm */
  u8 bArgList;               /* True for SQLITE_PRINTF_SQLFUNC */
  char prefix;               /* Prefix character.  "+" or "-" or " " or '\0'. */
  sqlite_uint64 longvalue;   /* Value for integer types */
  double realvalue;          /* Value for real types */
  const et_info *infop;      /* Pointer to the appropriate info structure */
  char *zOut;                /* Rendering buffer */
  int nOut;                  /* Size of the rendering buffer */
  char *zExtra = 0;          /* Malloced memory used by some conversion */
  int exp, e2;               /* exponent of real numbers */
  etByte flag_dp;            /* True if decimal point should be shown */
  etByte flag_rtz;           /* True if trailing zeros should be removed */

  PrintfArguments *pArgList = 0; /* Arguments for SQLITE_PRINTF_SQLFUNC */
  char buf[etBUFSIZE];       /* Conversion buffer */

  /* pAccum never starts out with an empty buffer that was obtained from 
  ** malloc().  This precondition is required by the mprintf("%z...")
  ** optimization. */
  assert( pAccum->nChar>0 || (pAccum->printfFlags&SQLITE_PRINTF_MALLOCED)==0 );

  bufpt = 0;
  if( (pAccum->printfFlags & SQLITE_PRINTF_SQLFUNC)!=0 ){
    pArgList = va_arg(ap, PrintfArguments*);
    bArgList = 1;
  }else{
    bArgList = 0;
  }
  for(; (c=(*fmt))!=0; ++fmt){
    if( c!='%' ){
      bufpt = (char *)fmt;
#if HAVE_STRCHRNUL
      fmt = strchrnul(fmt, '%');
#else
      fmt = strchr(fmt, '%');
      if( fmt==0 ){
        fmt = bufpt + strlen(bufpt);
      }
#endif
      sqlite3_str_append(pAccum, bufpt, (int)(fmt - bufpt));
      if( *fmt==0 ) break;
    }
    if( (c=(*++fmt))==0 ){
      sqlite3_str_append(pAccum, "%", 1);
      break;
    }
    /* Find out what flags are present */
    flag_leftjustify = flag_prefix = cThousand =
     flag_alternateform = flag_altform2 = flag_zeropad = 0;
    done = 0;
    width = 0;
    flag_long = 0;
    precision = -1;
    do{
      switch( c ){
        case '-':   flag_leftjustify = 1;     break;
        case '+':   flag_prefix = '+';        break;
        case ' ':   flag_prefix = ' ';        break;
        case '#':   flag_alternateform = 1;   break;
        case '!':   flag_altform2 = 1;        break;
        case '0':   flag_zeropad = 1;         break;
        case ',':   cThousand = ',';          break;
        default:    done = 1;                 break;
        case 'l': {
          flag_long = 1;
          c = *++fmt;
          if( c=='l' ){
            c = *++fmt;
            flag_long = 2;
          }
          done = 1;
          break;
        }
        case '1': case '2': case '3': case '4': case '5':
        case '6': case '7': case '8': case '9': {
          unsigned wx = c - '0';
          while( (c = *++fmt)>='0' && c<='9' ){
            wx = wx*10 + c - '0';
          }
          testcase( wx>0x7fffffff );
          width = wx & 0x7fffffff;
#ifdef SQLITE_PRINTF_PRECISION_LIMIT
          if( width>SQLITE_PRINTF_PRECISION_LIMIT ){
            width = SQLITE_PRINTF_PRECISION_LIMIT;
          }
#endif
          if( c!='.' && c!='l' ){
            done = 1;
          }else{
            fmt--;
          }
          break;
        }
        case '*': {
          if( bArgList ){
            width = (int)getIntArg(pArgList);
          }else{
            width = va_arg(ap,int);
          }
          if( width<0 ){
            flag_leftjustify = 1;
            width = width >= -2147483647 ? -width : 0;
          }
#ifdef SQLITE_PRINTF_PRECISION_LIMIT
          if( width>SQLITE_PRINTF_PRECISION_LIMIT ){
            width = SQLITE_PRINTF_PRECISION_LIMIT;
          }
#endif
          if( (c = fmt[1])!='.' && c!='l' ){
            c = *++fmt;
            done = 1;
          }
          break;
        }
        case '.': {
          c = *++fmt;
          if( c=='*' ){
            if( bArgList ){
              precision = (int)getIntArg(pArgList);
            }else{
              precision = va_arg(ap,int);
            }
            if( precision<0 ){
              precision = precision >= -2147483647 ? -precision : -1;
            }
            c = *++fmt;
          }else{
            unsigned px = 0;
            while( c>='0' && c<='9' ){
              px = px*10 + c - '0';
              c = *++fmt;
            }
            testcase( px>0x7fffffff );
            precision = px & 0x7fffffff;
          }
#ifdef SQLITE_PRINTF_PRECISION_LIMIT
          if( precision>SQLITE_PRINTF_PRECISION_LIMIT ){
            precision = SQLITE_PRINTF_PRECISION_LIMIT;
          }
#endif
          if( c=='l' ){
            --fmt;
          }else{
            done = 1;
          }
          break;
        }
      }
    }while( !done && (c=(*++fmt))!=0 );

    /* Fetch the info entry for the field */
#ifdef SQLITE_EBCDIC
    /* The hash table only works for ASCII.  For EBCDIC, we need to do
    ** a linear search of the table */
    infop = &fmtinfo[0];
    xtype = etINVALID;
    for(idx=0; idx<ArraySize(fmtinfo); idx++){
      if( c==fmtinfo[idx].fmttype ){
        infop = &fmtinfo[idx];
        xtype = infop->type;
        break;
      }
    }
#else
    /* Fast hash-table lookup */
    assert( ArraySize(fmtinfo)==23 );
    idx = ((unsigned)c) % 23;
    if( fmtinfo[idx].fmttype==c
     || fmtinfo[idx = fmtinfo[idx].iNxt].fmttype==c
    ){
      infop = &fmtinfo[idx];
      xtype = infop->type;
    }else{
      infop = &fmtinfo[0];
      xtype = etINVALID;
    }
#endif

    /*
    ** At this point, variables are initialized as follows:
    **
    **   flag_alternateform          TRUE if a '#' is present.
    **   flag_altform2               TRUE if a '!' is present.
    **   flag_prefix                 '+' or ' ' or zero
    **   flag_leftjustify            TRUE if a '-' is present or if the
    **                               field width was negative.
    **   flag_zeropad                TRUE if the width began with 0.
    **   flag_long                   1 for "l", 2 for "ll"
    **   width                       The specified field width.  This is
    **                               always non-negative.  Zero is the default.
    **   precision                   The specified precision.  The default
    **                               is -1.
    **   xtype                       The class of the conversion.
    **   infop                       Pointer to the appropriate info struct.
    */
    assert( width>=0 );
    assert( precision>=(-1) );
    switch( xtype ){
      case etPOINTER:
        flag_long = sizeof(char*)==sizeof(i64) ? 2 :
                     sizeof(char*)==sizeof(long int) ? 1 : 0;
        /* no break */ deliberate_fall_through
      case etORDINAL:
      case etRADIX:      
        cThousand = 0;
        /* no break */ deliberate_fall_through
      case etDECIMAL:
        if( infop->flags & FLAG_SIGNED ){
          i64 v;
          if( bArgList ){
            v = getIntArg(pArgList);
          }else if( flag_long ){
            if( flag_long==2 ){
              v = va_arg(ap,i64) ;
            }else{
              v = va_arg(ap,long int);
            }
          }else{
            v = va_arg(ap,int);
          }
          if( v<0 ){
            testcase( v==SMALLEST_INT64 );
            testcase( v==(-1) );
            longvalue = ~v;
            longvalue++;
            prefix = '-';
          }else{
            longvalue = v;
            prefix = flag_prefix;
          }
        }else{
          if( bArgList ){
            longvalue = (u64)getIntArg(pArgList);
          }else if( flag_long ){
            if( flag_long==2 ){
              longvalue = va_arg(ap,u64);
            }else{
              longvalue = va_arg(ap,unsigned long int);
            }
          }else{
            longvalue = va_arg(ap,unsigned int);
          }
          prefix = 0;
        }

#if WHERETRACE_ENABLED
        if( xtype==etPOINTER && sqlite3WhereTrace & 0x100000 ) longvalue = 0;
#endif
#if TREETRACE_ENABLED
        if( xtype==etPOINTER && sqlite3TreeTrace & 0x100000 ) longvalue = 0;
#endif

        if( longvalue==0 ) flag_alternateform = 0;
        if( flag_zeropad && precision<width-(prefix!=0) ){
          precision = width-(prefix!=0);
        }
        if( precision<etBUFSIZE-10-etBUFSIZE/3 ){
          nOut = etBUFSIZE;
          zOut = buf;
        }else{
          u64 n;
          n = (u64)precision + 10;
          if( cThousand ) n += precision/3;
          zOut = zExtra = printfTempBuf(pAccum, n);
          if( zOut==0 ) return;
          nOut = (int)n;
        }
        bufpt = &zOut[nOut-1];
        if( xtype==etORDINAL ){
          static const char zOrd[] = "thstndrd";
          int x = (int)(longvalue % 10);
          if( x>=4 || (longvalue/10)%10==1 ){
            x = 0;
          }
          *(--bufpt) = zOrd[x*2+1];
          *(--bufpt) = zOrd[x*2];
        }
        {
          const char *cset = &aDigits[infop->charset];
          u8 base = infop->base;
          do{                                           /* Convert to ascii */
            *(--bufpt) = cset[longvalue%base];
            longvalue = longvalue/base;
          }while( longvalue>0 );
        }
        length = (int)(&zOut[nOut-1]-bufpt);
        if( precision>length ){                         /* zero pad */
          int nn = precision-length;
          bufpt -= nn;
          memset(bufpt,'0',nn);
          length = precision;
        }
        if( cThousand ){
          int nn = (length - 1)/3;  /* Number of "," to insert */
          int ix = (length - 1)%3 + 1;
          bufpt -= nn;
          for(idx=0; nn>0; idx++){
            bufpt[idx] = bufpt[idx+nn];
            ix--;
            if( ix==0 ){
              bufpt[++idx] = cThousand;
              nn--;
              ix = 3;
            }
          }
        }
        if( prefix ) *(--bufpt) = prefix;               /* Add sign */
        if( flag_alternateform && infop->prefix ){      /* Add "0" or "0x" */
          const char *pre;
          char x;
          pre = &aPrefix[infop->prefix];
          for(; (x=(*pre))!=0; pre++) *(--bufpt) = x;
        }
        length = (int)(&zOut[nOut-1]-bufpt);
        break;
      case etFLOAT:
      case etEXP:
      case etGENERIC: {
        FpDecode s;
        int iRound;
        int j;
        i64 szBufNeeded;       /* Size needed to hold the output */

        if( bArgList ){
          realvalue = getDoubleArg(pArgList);
        }else{
          realvalue = va_arg(ap,double);
        }
        if( precision<0 ) precision = 6;         /* Set default precision */
#ifdef SQLITE_FP_PRECISION_LIMIT
        if( precision>SQLITE_FP_PRECISION_LIMIT ){
          precision = SQLITE_FP_PRECISION_LIMIT;
        }
#endif
        if( xtype==etFLOAT ){
          iRound = -precision;
        }else if( xtype==etGENERIC ){
          if( precision==0 ) precision = 1;
          iRound = precision;
        }else{
          iRound = precision+1;
        }
        sqlite3FpDecode(&s, realvalue, iRound, flag_altform2 ? 20 : 16);
        if( s.isSpecial ){
          if( s.isSpecial==2 ){
            bufpt = flag_zeropad ? "null" : "NaN";
            length = sqlite3Strlen30(bufpt);
            break;
          }else if( flag_zeropad ){
            s.z[0] = '9';
            s.iDP = 1000;
            s.n = 1;
          }else{
            memcpy(buf, "-Inf", 5);
            bufpt = buf;
            if( s.sign=='-' ){
              /* no-op */
            }else if( flag_prefix ){
              buf[0] = flag_prefix;
            }else{
              bufpt++;
            }
            length = sqlite3Strlen30(bufpt);
            break;
          }
        }
        if( s.sign=='-' ){
          if( flag_alternateform
           && !flag_prefix
           && xtype==etFLOAT
           && s.iDP<=iRound
          ){
            /* Suppress the minus sign if all of the following are true:
            **   *  The value displayed is zero
            **   *  The '#' flag is used
            **   *  The '+' flag is not used, and
            **   *  The format is %f
            */
            prefix = 0;
          }else{
            prefix = '-';
          }
        }else{
          prefix = flag_prefix;
        }

        exp = s.iDP-1;

        /*
        ** If the field type is etGENERIC, then convert to either etEXP
        ** or etFLOAT, as appropriate.
        */
        if( xtype==etGENERIC ){
          assert( precision>0 );
          precision--;
          flag_rtz = !flag_alternateform;
          if( exp<-4 || exp>precision ){
            xtype = etEXP;
          }else{
            precision = precision - exp;
            xtype = etFLOAT;
          }
        }else{
          flag_rtz = flag_altform2;
        }
        if( xtype==etEXP ){
          e2 = 0;
        }else{
          e2 = s.iDP - 1;
        }

        szBufNeeded = MAX(e2,0)+(i64)precision+(i64)width+8;
        if( cThousand && e2>0 ) szBufNeeded += (e2+2)/3;
        if( sqlite3StrAccumEnlargeIfNeeded(pAccum, szBufNeeded) ){
          width = length = 0;
          break;
        }
        bufpt = zOut = pAccum->zText + pAccum->nChar;

        flag_dp = (precision>0 ?1:0) | flag_alternateform | flag_altform2;
        /* The sign in front of the number */
        if( prefix ){
          *(bufpt++) = prefix;
        }
        /* Digits prior to the decimal point */
        j = 0;
        assert( s.n>0 );
        if( e2<0 ){
          *(bufpt++) = '0';
        }else if( cThousand ){
          for(; e2>=0; e2--){
            *(bufpt++) = j<s.n ? s.z[j++] : '0';
            if( (e2%3)==0 && e2>1 ) *(bufpt++) = ',';
          }
        }else{
          j = e2+1;
          if( j>s.n ) j = s.n;
          memcpy(bufpt, s.z, j);
          bufpt += j;
          e2 -= j;
          if( e2>=0 ){
            memset(bufpt, '0', e2+1);
            bufpt += e2+1;
            e2 = -1;
          }
        }
        /* The decimal point */
        if( flag_dp ){
          *(bufpt++) = '.';
        }
        /* "0" digits after the decimal point but before the first
        ** significant digit of the number */
        if( e2<(-1) && precision>0 ){
          int nn = -1-e2;
          if( nn>precision ) nn = precision;
          memset(bufpt, '0', nn);
          bufpt += nn;
          precision -= nn;
        }
        /* Significant digits after the decimal point */
        if( precision>0 ){
          int nn = s.n - j;
          if( NEVER(nn>precision) ) nn = precision;
          if( nn>0 ){
            memcpy(bufpt, s.z+j, nn);
            bufpt += nn;
            precision -= nn;
          }
          if( precision>0 && !flag_rtz ){
            memset(bufpt, '0', precision);
            bufpt += precision;
          }
        }
        /* Remove trailing zeros and the "." if no digits follow the "." */
        if( flag_rtz && flag_dp ){
          while( bufpt[-1]=='0' ) *(--bufpt) = 0;
          assert( bufpt>zOut );
          if( bufpt[-1]=='.' ){
            if( flag_altform2 ){
              *(bufpt++) = '0';
            }else{
              *(--bufpt) = 0;
            }
          }
        }
        /* Add the "eNNN" suffix */
        if( xtype==etEXP ){
          exp = s.iDP - 1;
          *(bufpt++) = aDigits[infop->charset];
          if( exp<0 ){
            *(bufpt++) = '-'; exp = -exp;
          }else{
            *(bufpt++) = '+';
          }
          if( exp>=100 ){
            *(bufpt++) = (char)((exp/100)+'0');        /* 100's digit */
            exp %= 100;
          }
          *(bufpt++) = (char)(exp/10+'0');             /* 10's digit */
          *(bufpt++) = (char)(exp%10+'0');             /* 1's digit */
        }

        length = (int)(bufpt-zOut);
        assert( length <= szBufNeeded );
        if( length<width ){
          i64 nPad = width - length;
          if( flag_leftjustify ){
            memset(bufpt, ' ', nPad);
          }else if( !flag_zeropad ){
            memmove(zOut+nPad, zOut, length);
            memset(zOut, ' ', nPad);
          }else{
            int adj = prefix!=0;
            memmove(zOut+nPad+adj, zOut+adj, length-adj);
            memset(zOut+adj, '0', nPad);
          }
          length = width;
        }
        pAccum->nChar += length;
        zOut[length] = 0;

        /* Floating point conversions render directly into the output
        ** buffer.  Hence, don't just break out of the switch().  Bypass the
        ** output buffer writing that occurs after the switch() by continuing
        ** to the next character in the format string. */
        continue;
      }
      case etSIZE:
        if( !bArgList ){
          *(va_arg(ap,int*)) = pAccum->nChar;
        }
        length = width = 0;
        break;
      case etPERCENT:
        buf[0] = '%';
        bufpt = buf;
        length = 1;
        break;
      case etCHARX:
        if( bArgList ){
          bufpt = getTextArg(pArgList);
          length = 1;
          if( bufpt ){
            buf[0] = c = *(bufpt++);
            if( (c&0xc0)==0xc0 ){
              while( length<4 && (bufpt[0]&0xc0)==0x80 ){
                buf[length++] = *(bufpt++);
              }
            }
          }else{
            buf[0] = 0;
          }
        }else{
          unsigned int ch = va_arg(ap,unsigned int);
          length = sqlite3AppendOneUtf8Character(buf, ch);
        }
        if( precision>1 ){
          i64 nPrior = 1;
          width -= precision-1;
          if( width>1 && !flag_leftjustify ){
            sqlite3_str_appendchar(pAccum, width-1, ' ');
            width = 0;
          }
          sqlite3_str_append(pAccum, buf, length);
          precision--;
          while( precision > 1 ){
            i64 nCopyBytes;
            if( nPrior > precision-1 ) nPrior = precision - 1;
            nCopyBytes = length*nPrior;
            if( sqlite3StrAccumEnlargeIfNeeded(pAccum, nCopyBytes) ){
              break;
            }
           sqlite3_str_append(pAccum,
                 &pAccum->zText[pAccum->nChar-nCopyBytes], nCopyBytes);
            precision -= nPrior;
            nPrior *= 2;
          }
        }
        bufpt = buf;
        flag_altform2 = 1;
        goto adjust_width_for_utf8;
      case etSTRING:
      case etDYNSTRING:
        if( bArgList ){
          bufpt = getTextArg(pArgList);
          xtype = etSTRING;
        }else{
          bufpt = va_arg(ap,char*);
        }
        if( bufpt==0 ){
          bufpt = "";
        }else if( xtype==etDYNSTRING ){
          if( pAccum->nChar==0
           && pAccum->mxAlloc
           && width==0
           && precision<0
           && pAccum->accError==0
          ){
            /* Special optimization for sqlite3_mprintf("%z..."):
            ** Extend an existing memory allocation rather than creating
            ** a new one. */
            assert( (pAccum->printfFlags&SQLITE_PRINTF_MALLOCED)==0 );
            pAccum->zText = bufpt;
            pAccum->nAlloc = sqlite3DbMallocSize(pAccum->db, bufpt);
            pAccum->nChar = 0x7fffffff & (int)strlen(bufpt);
            pAccum->printfFlags |= SQLITE_PRINTF_MALLOCED;
            length = 0;
            break;
          }
          zExtra = bufpt;
        }
        if( precision>=0 ){
          if( flag_altform2 ){
            /* Set length to the number of bytes needed in order to display
            ** precision characters */
            unsigned char *z = (unsigned char*)bufpt;
            while( precision-- > 0 && z[0] ){
              SQLITE_SKIP_UTF8(z);
            }
            length = (int)(z - (unsigned char*)bufpt);
          }else{
            for(length=0; length<precision && bufpt[length]; length++){}
          }
        }else{
          length = 0x7fffffff & (int)strlen(bufpt);
        }
      adjust_width_for_utf8:
        if( flag_altform2 && width>0 ){
          /* Adjust width to account for extra bytes in UTF-8 characters */
          int ii = length - 1;
          while( ii>=0 ) if( (bufpt[ii--] & 0xc0)==0x80 ) width++;
        }
        break;
      case etESCAPE_q:          /* %q: Escape ' characters */
      case etESCAPE_Q:          /* %Q: Escape ' and enclose in '...' */
      case etESCAPE_w: {        /* %w: Escape " characters */
        i64 i, j, k, n;
        int needQuote = 0;
        char ch;
        char *escarg;
        char q;

        if( bArgList ){
          escarg = getTextArg(pArgList);
        }else{
          escarg = va_arg(ap,char*);
        }
        if( escarg==0 ){
          escarg = (xtype==etESCAPE_Q ? "NULL" : "(NULL)");
        }else if( xtype==etESCAPE_Q ){
          needQuote = 1;
        }
        if( xtype==etESCAPE_w ){
          q = '"';
          flag_alternateform = 0;
        }else{
          q = '\'';
        }
        /* For %q, %Q, and %w, the precision is the number of bytes (or
        ** characters if the ! flags is present) to use from the input.
        ** Because of the extra quoting characters inserted, the number
        ** of output characters may be larger than the precision.
        */
        k = precision;
        for(i=n=0; k!=0 && (ch=escarg[i])!=0; i++, k--){
          if( ch==q )  n++;
          if( flag_altform2 && (ch&0xc0)==0xc0 ){
            while( (escarg[i+1]&0xc0)==0x80 ){ i++; }
          }
        }
        if( flag_alternateform ){
          /* For %#q, do unistr()-style backslash escapes for
          ** all control characters, and for backslash itself.
          ** For %#Q, do the same but only if there is at least
          ** one control character. */
          u32 nBack = 0;
          u32 nCtrl = 0;
          for(k=0; k<i; k++){
            if( escarg[k]=='\\' ){
              nBack++;
            }else if( ((u8*)escarg)[k]<=0x1f ){
              nCtrl++;
            }
          }
          if( nCtrl || xtype==etESCAPE_q ){
            n += nBack + 5*nCtrl;
            if( xtype==etESCAPE_Q ){
              n += 10;
              needQuote = 2;
            }
          }else{
            flag_alternateform = 0;
          }
        }
        n += i + 3;
        if( n>etBUFSIZE ){
          bufpt = zExtra = printfTempBuf(pAccum, n);
          if( bufpt==0 ) return;
        }else{
          bufpt = buf;
        }
        j = 0;
        if( needQuote ){
          if( needQuote==2 ){
            memcpy(&bufpt[j], "unistr('", 8);
            j += 8;
          }else{
            bufpt[j++] = '\'';
          }
        }
        k = i;
        if( flag_alternateform ){
          for(i=0; i<k; i++){
            bufpt[j++] = ch = escarg[i];
            if( ch==q ){
              bufpt[j++] = ch;
            }else if( ch=='\\' ){
              bufpt[j++] = '\\';
            }else if( ((unsigned char)ch)<=0x1f ){
              bufpt[j-1] = '\\';
              bufpt[j++] = 'u';
              bufpt[j++] = '0';
              bufpt[j++] = '0';
              bufpt[j++] = ch>=0x10 ? '1' : '0';
              bufpt[j++] = "0123456789abcdef"[ch&0xf];
            }
          }
        }else{
          for(i=0; i<k; i++){
            bufpt[j++] = ch = escarg[i];
            if( ch==q ) bufpt[j++] = ch;
          }
        }
        if( needQuote ){
          bufpt[j++] = '\'';
          if( needQuote==2 ) bufpt[j++] = ')';
        }
        bufpt[j] = 0;
        length = j;
        goto adjust_width_for_utf8;
      }
      case etTOKEN: {
        if( (pAccum->printfFlags & SQLITE_PRINTF_INTERNAL)==0 ) return;
        if( flag_alternateform ){
          /* %#T means an Expr pointer that uses Expr.u.zToken */
          Expr *pExpr = va_arg(ap,Expr*);
          if( ALWAYS(pExpr) && ALWAYS(!ExprHasProperty(pExpr,EP_IntValue)) ){
            sqlite3_str_appendall(pAccum, (const char*)pExpr->u.zToken);
            sqlite3RecordErrorOffsetOfExpr(pAccum->db, pExpr);
          }
        }else{
          /* %T means a Token pointer */
          Token *pToken = va_arg(ap, Token*);
          assert( bArgList==0 );
          if( pToken && pToken->n ){
            sqlite3_str_append(pAccum, (const char*)pToken->z, pToken->n);
            sqlite3RecordErrorByteOffset(pAccum->db, pToken->z);
          }
        }
        length = width = 0;
        break;
      }
      case etSRCITEM: {
        SrcItem *pItem;
        if( (pAccum->printfFlags & SQLITE_PRINTF_INTERNAL)==0 ) return;
        pItem = va_arg(ap, SrcItem*);
        assert( bArgList==0 );
        if( pItem->zAlias && !flag_altform2 ){
          sqlite3_str_appendall(pAccum, pItem->zAlias);
        }else if( pItem->zName ){
          if( pItem->fg.fixedSchema==0
           && pItem->fg.isSubquery==0
           && pItem->u4.zDatabase!=0
          ){
            sqlite3_str_appendall(pAccum, pItem->u4.zDatabase);
            sqlite3_str_append(pAccum, ".", 1);
          }
          sqlite3_str_appendall(pAccum, pItem->zName);
        }else if( pItem->zAlias ){
          sqlite3_str_appendall(pAccum, pItem->zAlias);
        }else if( ALWAYS(pItem->fg.isSubquery) ){/* Because of tag-20240424-1 */
          Select *pSel = pItem->u4.pSubq->pSelect;
          assert( pSel!=0 ); 
          if( pSel->selFlags & SF_NestedFrom ){
            sqlite3_str_appendf(pAccum, "(join-%u)", pSel->selId);
          }else if( pSel->selFlags & SF_MultiValue ){
            assert( !pItem->fg.isTabFunc && !pItem->fg.isIndexedBy );
            sqlite3_str_appendf(pAccum, "%u-ROW VALUES CLAUSE",
                                pItem->u1.nRow);
          }else{
            sqlite3_str_appendf(pAccum, "(subquery-%u)", pSel->selId);
          }
        }
        length = width = 0;
        break;
      }
      default: {
        assert( xtype==etINVALID );
        return;
      }
    }/* End switch over the format type */
    /*
    ** The text of the conversion is pointed to by "bufpt" and is
    ** "length" characters long.  The field width is "width".  Do
    ** the output.  Both length and width are in bytes, not characters,
    ** at this point.  If the "!" flag was present on string conversions
    ** indicating that width and precision should be expressed in characters,
    ** then the values have been translated prior to reaching this point.
    */
    width -= length;
    if( width>0 ){
      if( !flag_leftjustify ) sqlite3_str_appendchar(pAccum, width, ' ');
      sqlite3_str_append(pAccum, bufpt, length);
      if( flag_leftjustify ) sqlite3_str_appendchar(pAccum, width, ' ');
    }else{
      sqlite3_str_append(pAccum, bufpt, length);
    }

    if( zExtra ){
      sqlite3DbFree(pAccum->db, zExtra);
      zExtra = 0;
    }
  }/* End for loop over the format string */
}
```

## Bug Fix Patch

```diff
diff --git a/manifest b/manifest
index aa86baff50..8346aba359 100644
--- a/manifest
+++ b/manifest
@@ -1,5 +1,5 @@
-C Fix\sa\sfew\sdoc\stypos\sand\sinconsistencies.\sNo\scode\schanges.
-D 2026-04-07T15:54:35.800
+C Fix\sa\sbuffer\soverflow\sbug\sin\sa\srecent\scheck-in,\sreported\sby\sunsolicted\nemail\sfrom\sOpenAI/Codex.
+D 2026-04-08T17:00:33.995
 F .fossil-settings/binary-glob 61195414528fb3ea9693577e1980230d78a1f8b0a54c78cf1b9b24d0a409ed6a x
 F .fossil-settings/empty-dirs dbb81e8fc0401ac46a1491ab34a7f2c7c0452f2f06b54ebb845d024ca8283ef1
 F .fossil-settings/ignore-glob 35175cdfcf539b2318cb04a9901442804be81cd677d8b889fcc9149c21f239ea
@@ -730,7 +730,7 @@ F src/pcache.h 092b758d2c5e4dabb30eae46d8dfad77c0f70b16bf3ff1943f7a232b0fe0d4ba
 F src/pcache1.c 131ca0daf4e66b4608d2945ae76d6ed90de3f60539afbd5ef9ec65667a5f2fcd
 F src/pragma.c 789ef67117b74b5be0a2db6681f7f0c55e6913791b9da309aefd280de2c8a74d
 F src/prepare.c f6a6e28a281bd1d1da12f47d370a81af46159b40f73bf7fa0b276b664f9c8b7d
-F src/printf.c 9abec48ffb0fc1aac72a461e2ca456b5284a39c84cddc932c86822311e059882
+F src/printf.c 41fb76fcb5ed7e16aaddc659d3b23891abebea45549fe125fc2e6ec380cc7175
 F src/random.c 606b00941a1d7dd09c381d3279a058d771f406c5213c9932bbd93d5587be4b9c
 F src/resolve.c 928ff887f2a7c64275182060d94d06fdddbe32226c569781cf7e7edc6f58d7fd
 F src/rowset.c 8432130e6c344b3401a8874c3cb49fefe6873fec593294de077afea2dce5ec97
@@ -1514,7 +1514,7 @@ F test/pragma5.test 7b33fc43e2e41abf17f35fb73f71b49671a380ea92a6c94b6ce530a25f8d
 F test/pragma6.test c5ec577ba087954b4dfa619a3cbe97b155b60a0af487527abe89b10fc17e6512
 F test/pragmafault.test 275edaf3161771d37de60e5c2b412627ac94cef11739236bec12ed1258b240f8
 F test/prefixes.test b524a1c44bffec225b9aec98bd728480352aa8532ac4c15771fb85e8beef65d9
-F test/printf.test 685fec5a0c5af2490ab0632775a301554361d674211d690f5bee0a97b05333de
+F test/printf.test bcb093ef5cbd17e2d94d93d62045ee61ed0f465c1ca123f284774e474e73a9ea
 F test/printf2.test 3f55c1871a5a65507416076f6eb97e738d5210aeda7595a74ee895f2224cce60
 F test/progress.test ebab27f670bd0d4eb9d20d49cef96e68141d92fb
 F test/ptrchng.test ef1aa72d6cf35a2bbd0869a649b744e9d84977fc
@@ -2197,8 +2197,8 @@ F tool/warnings-clang.sh bbf6a1e685e534c92ec2bfba5b1745f34fb6f0bc2a362850723a9ee
 F tool/warnings.sh a554d13f6e5cf3760f041b87939e3d616ec6961859c3245e8ef701d1eafc2ca2
 F tool/win/sqlite.vsix deb315d026cc8400325c5863eef847784a219a2f
 F tool/winmain.c 00c8fb88e365c9017db14c73d3c78af62194d9644feaf60e220ab0f411f3604c
-P 4a36454904e1c5e7d25406713ab0125f11df66eabe0d378edcb837ef8dedc981
-R 16f1b21b4cb5faffe725c6e07d5c25a3
-U stephan
-Z 22c44324ea68c832a57d85b95caa6e8a
+P 025abd4cf409fb9938e116289f23dc5bcd6d14feb46066221e691b146ee9b354
+R 7600f47bef4b02dcc59e25059aaa900d
+U drh
+Z c818e025424851b4793e1d43a62d77e7
 # Remove this line to create a well-formed Fossil manifest.
diff --git a/manifest.uuid b/manifest.uuid
index 832bf071a8..9731891d07 100644
--- a/manifest.uuid
+++ b/manifest.uuid
@@ -1 +1 @@
-025abd4cf409fb9938e116289f23dc5bcd6d14feb46066221e691b146ee9b354
+be891a137af15897691250324e4d3d9c96f0c5fb414bca27d0c3bfdd3012a8a2
diff --git a/src/printf.c b/src/printf.c
index 257fcb3757..c9fc1a72c0 100644
--- a/src/printf.c
+++ b/src/printf.c
@@ -621,7 +621,7 @@ void sqlite3_str_vappendf(
           e2 = s.iDP - 1;
         }
 
-        szBufNeeded = MAX(e2,0)+(i64)precision+(i64)width+8;
+        szBufNeeded = MAX(e2,0)+(i64)precision+(i64)width+10;
         if( cThousand && e2>0 ) szBufNeeded += (e2+2)/3;
         if( sqlite3StrAccumEnlargeIfNeeded(pAccum, szBufNeeded) ){
           width = length = 0;
diff --git a/test/printf.test b/test/printf.test
index cc439e6172..1f8ab25a59 100644
--- a/test/printf.test
+++ b/test/printf.test
@@ -3823,6 +3823,11 @@ do_execsql_test printf-17.11 {
   SELECT format('%.30f',1.0000000000000000076e-50);
 } 0.000000000000000000000000000000
 
+# Reported by OpenAI Codex Security on 2026-04-08
+do_execsql_test printf-17.12 {
+  SELECT format('%!.0e',-1e100);
+} -1.0e+100
+
 #-------------------------------------------------------------------------
 # dbsqlfuzz ad651aad4bb2100f3a724129a555d8d773366d46
 #
```
