using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Crypture
{
    internal static class TotpQrDecoder
    {
        private readonly record struct Finder(double X, double Y, double Module, int Hits);

        // QR Model 2 block counts and parity bytes, indexed by format level (M, L, H, Q) and version.
        private static readonly byte[][] BlockCounts =
        [
            [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
                17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
            [1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
                8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
            [1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25,
                25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
            [1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20,
                23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68]
        ];
        private static readonly byte[][] ParityCounts =
        [
            [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
                26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
            [7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
                28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
            [17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28,
                30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
            [13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30,
                28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
        ];
        private static readonly byte[] oExponents = new byte[510];
        private static readonly byte[] oLogarithms = new byte[256];
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);

        static TotpQrDecoder()
        {
            // QR error correction operates in GF(256) with the primitive polynomial x^8+x^4+x^3+x^2+1.
            int nValue = 1;
            for (int nIndex = 0; nIndex < 255; nIndex++)
            {
                oExponents[nIndex] = oExponents[nIndex + 255] = (byte)nValue;
                oLogarithms[nValue] = (byte)nIndex;
                nValue <<= 1;
                if (nValue >= 256) nValue ^= 0x11D;
            }
        }

        internal static string[] Decode(Span<byte> oPixels, int nWidth, int nHeight)
        {
            // Reuse consumed BGRA bytes for brightness; the caller clears this temporary pixel buffer.
            Span<byte> oGray = oPixels[..(nWidth * nHeight)];
            bool[] oDark = new bool[oGray.Length];
            try
            {
                // Composite transparent pixels on white before measuring brightness.
                Span<int> oHistogram = stackalloc int[256];
                oHistogram.Clear();
                for (int nPixel = 0; nPixel < oGray.Length; nPixel++)
                {
                    int nOffset = nPixel * 4;
                    int nAlpha = oPixels[nOffset + 3];
                    int nGray = (77 * oPixels[nOffset + 2] + 150 * oPixels[nOffset + 1] +
                        29 * oPixels[nOffset]) >> 8;
                    oGray[nPixel] = (byte)((nGray * nAlpha + 255 * (255 - nAlpha) + 127) / 255);
                    oHistogram[oGray[nPixel]]++;
                }

                // Otsu's threshold separates foreground and background without assuming their colors.
                long nSum = 0, nLowerSum = 0;
                for (int nValue = 0; nValue < 256; nValue++) nSum += (long)nValue * oHistogram[nValue];
                int nLowerCount = 0, nFirstThreshold = 128, nLastThreshold = 128;
                double nBestVariance = 0;
                for (int nValue = 0; nValue < 255; nValue++)
                {
                    nLowerCount += oHistogram[nValue];
                    nLowerSum += (long)nValue * oHistogram[nValue];
                    int nUpperCount = oGray.Length - nLowerCount;
                    if (nLowerCount == 0 || nUpperCount == 0) continue;
                    double nDifference = (double)nLowerSum / nLowerCount - (double)(nSum - nLowerSum) / nUpperCount;
                    double nVariance = (double)nLowerCount * nUpperCount * nDifference * nDifference;
                    if (nVariance > nBestVariance)
                    {
                        nBestVariance = nVariance;
                        nFirstThreshold = nLastThreshold = nValue;
                    }
                    else if (nVariance == nBestVariance) nLastThreshold = nValue;
                }
                int nThreshold = (nFirstThreshold + nLastThreshold) / 2;
                for (int nPixel = 0; nPixel < oGray.Length; nPixel++) oDark[nPixel] = oGray[nPixel] <= nThreshold;

                // Scan the entire image in both polarities so another setup cannot be overlooked.
                HashSet<string> oResults = new HashSet<string>(StringComparer.Ordinal);
                for (int nPolarity = 0; nPolarity < 2; nPolarity++)
                {
                    FindCodes(oDark, nWidth, nHeight, oResults);
                    for (int nPixel = 0; nPixel < oDark.Length; nPixel++) oDark[nPixel] = !oDark[nPixel];
                }
                return oResults.ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oGray);
                Array.Clear(oDark);
            }
        }

        private static bool IsFinder(ReadOnlySpan<int> oRuns)
        {
            int nTotal = 0;
            foreach (int nRun in oRuns)
            {
                if (nRun == 0) return false;
                nTotal += nRun;
            }
            if (nTotal < 7) return false;
            double nModule = nTotal / 7d;
            for (int nRun = 0; nRun < 5; nRun++)
                if (Math.Abs(oRuns[nRun] - nModule * (nRun == 2 ? 3 : 1)) >
                    nModule * (nRun == 2 ? 1.25 : 0.75)) return false;
            return true;
        }

        private static bool CrossCheck(bool[] oDark, int nWidth, int nHeight, int nX, int nY,
            int nDx, int nDy, double nModule, out double nCenter, out double nSize)
        {
            Span<int> oRuns = stackalloc int[5];
            oRuns.Clear();
            int nLimit = (int)Math.Ceiling(nModule * 5);
            int nPositive = 0;
            for (int nDirection = -1; nDirection <= 1; nDirection += 2)
            {
                int nStep = 0;
                for (int nRun = 2; nRun >= 0; nRun--)
                {
                    int nCount = 0;
                    while (nCount <= nLimit)
                    {
                        int nSampleX = nX + nStep * nDirection * nDx;
                        int nSampleY = nY + nStep * nDirection * nDy;
                        if ((uint)nSampleX >= nWidth || (uint)nSampleY >= nHeight ||
                            oDark[nSampleY * nWidth + nSampleX] != (nRun != 1)) break;
                        nStep++;
                        nCount++;
                    }
                    oRuns[nDirection < 0 ? nRun : 4 - nRun] += nCount;
                    if (nDirection > 0 && nRun == 2) nPositive = nCount;
                }
            }
            oRuns[2]--;
            nSize = (oRuns[0] + oRuns[1] + oRuns[2] + oRuns[3] + oRuns[4]) / 7d;
            nCenter = 0;
            if (!IsFinder(oRuns) || nSize < nModule * 0.6 || nSize > nModule * 1.6) return false;

            // Recover the middle of the central run rather than the row that first found the pattern.
            nCenter = (nDx == 0 ? nY : nX) + nPositive - oRuns[2] / 2d;
            return true;
        }

        private static List<Finder> FindPatterns(bool[] oDark, int nWidth, int nHeight)
        {
            List<Finder> oFinders = [];
            Span<int> oRuns = stackalloc int[5];
            for (int nY = 0; nY < nHeight; nY++)
            {
                oRuns.Clear();
                int nLength = 0;
                bool bDark = oDark[nY * nWidth];
                for (int nX = 0; nX <= nWidth; nX++)
                {
                    if (nX < nWidth && oDark[nY * nWidth + nX] == bDark)
                    {
                        nLength++;
                        continue;
                    }
                    oRuns[1..].CopyTo(oRuns);
                    oRuns[4] = nLength;
                    if (bDark && IsFinder(oRuns))
                    {
                        double nCenterX = nX - oRuns[4] - oRuns[3] - oRuns[2] / 2d;
                        double nModule = (oRuns[0] + oRuns[1] + oRuns[2] + oRuns[3] + oRuns[4]) / 7d;
                        if (CrossCheck(oDark, nWidth, nHeight, (int)nCenterX, nY, 0, 1,
                            nModule, out double nCenterY, out double nVerticalSize) &&
                            CrossCheck(oDark, nWidth, nHeight, (int)nCenterX, (int)nCenterY, 1, 0,
                                nVerticalSize, out nCenterX, out double nHorizontalSize))
                        {
                            nModule = (nVerticalSize + nHorizontalSize) / 2;
                            int nMatch = oFinders.FindIndex(f => Math.Abs(f.X - nCenterX) <= nModule &&
                                Math.Abs(f.Y - nCenterY) <= nModule && Math.Abs(f.Module - nModule) <= nModule);
                            if (nMatch >= 0)
                            {
                                Finder oOld = oFinders[nMatch];
                                int nHits = oOld.Hits + 1;
                                oFinders[nMatch] = new Finder((oOld.X * oOld.Hits + nCenterX) / nHits,
                                    (oOld.Y * oOld.Hits + nCenterY) / nHits,
                                    (oOld.Module * oOld.Hits + nModule) / nHits, nHits);
                            }
                            else
                            {
                                if (oFinders.Count >= 96) throw ComplexImage();
                                oFinders.Add(new Finder(nCenterX, nCenterY, nModule, 1));
                            }
                        }
                    }
                    bDark = !bDark;
                    nLength = 1;
                }
            }
            return oFinders.Where(f => f.Hits >= 2).OrderByDescending(f => f.Hits).ToList();
        }

        private static InvalidOperationException ComplexImage() => new InvalidOperationException(
            "Choose an image containing a setup QR code, and crop it to the code if the image is too large.");

        private static void FindCodes(bool[] oDark, int nWidth, int nHeight, HashSet<string> oResults)
        {
            List<Finder> oFinders = FindPatterns(oDark, nWidth, nHeight);
            bool[] oUsed = new bool[oFinders.Count];
            int nAttempts = 0;
            for (int nA = 0; nA < oFinders.Count; nA++)
            for (int nB = nA + 1; nB < oFinders.Count; nB++)
            for (int nC = nB + 1; nC < oFinders.Count; nC++)
            {
                if (oUsed[nA] || oUsed[nB] || oUsed[nC]) continue;
                Finder oCorner = oFinders[nA], oRight = oFinders[nB], oBottom = oFinders[nC];
                double Distance(Finder a, Finder b) => Math.Pow(a.X - b.X, 2) + Math.Pow(a.Y - b.Y, 2);
                double nAB = Distance(oCorner, oRight), nAC = Distance(oCorner, oBottom);
                double nBC = Distance(oRight, oBottom);
                if (nAB > nAC && nAB > nBC) (oCorner, oBottom) = (oBottom, oCorner);
                else if (nAC > nBC) (oCorner, oRight) = (oRight, oCorner);

                // The three large finder squares define orientation and the two module axes.
                double nDx = oRight.X - oCorner.X, nDy = oRight.Y - oCorner.Y;
                double nEx = oBottom.X - oCorner.X, nEy = oBottom.Y - oCorner.Y;
                double nHorizontal = Math.Sqrt(nDx * nDx + nDy * nDy);
                double nVertical = Math.Sqrt(nEx * nEx + nEy * nEy);
                double nModule = (oCorner.Module + oRight.Module + oBottom.Module) / 3;
                if (Math.Min(nHorizontal, nVertical) < 9 * nModule ||
                    Math.Max(nHorizontal, nVertical) > Math.Min(nHorizontal, nVertical) * 1.5 ||
                    Math.Abs(nDx * nEx + nDy * nEy) > nHorizontal * nVertical * 0.25 ||
                    Math.Max(oCorner.Module, Math.Max(oRight.Module, oBottom.Module)) >
                        Math.Min(oCorner.Module, Math.Min(oRight.Module, oBottom.Module)) * 1.8) continue;
                if (nDx * nEy - nDy * nEx < 0) (oRight, oBottom) = (oBottom, oRight);

                // Measure along the symbol axes; horizontal scans overestimate rotated finder widths.
                double[] oMeasured =
                [
                    MeasureModule(oDark, nWidth, nHeight, oCorner, oRight),
                    MeasureModule(oDark, nWidth, nHeight, oRight, oCorner),
                    MeasureModule(oDark, nWidth, nHeight, oCorner, oBottom),
                    MeasureModule(oDark, nWidth, nHeight, oBottom, oCorner)
                ];
                nModule = oMeasured.Where(s => s > 0).DefaultIfEmpty(nModule).Average();
                int nEstimatedVersion = (int)Math.Round(((nHorizontal + nVertical) / (2 * nModule) - 10) / 4);
                foreach (int nVersion in new[] { nEstimatedVersion, nEstimatedVersion - 1, nEstimatedVersion + 1 })
                {
                    if (nVersion is < 1 or > 40) continue;
                    bool[] oModules = Sample(oDark, nWidth, nHeight, oCorner, oRight, oBottom, nVersion);
                    if (oModules == null) continue;
                    try
                    {
                        if (++nAttempts > 256) throw ComplexImage();
                        string sText = DecodeModules(oModules, nVersion, false) ??
                            DecodeModules(oModules, nVersion, true);
                        if (sText == null) continue;
                        oResults.Add(sText);
                        oUsed[nA] = oUsed[nB] = oUsed[nC] = true;
                        break;
                    }
                    finally { Array.Clear(oModules); }
                }
            }
        }

        private static double MeasureModule(bool[] oDark, int nWidth, int nHeight, Finder oFrom, Finder oTo)
        {
            double nLength = Math.Sqrt(Math.Pow(oFrom.X - oTo.X, 2) + Math.Pow(oFrom.Y - oTo.Y, 2));
            double nDx = (oTo.X - oFrom.X) / nLength, nDy = (oTo.Y - oFrom.Y) / nLength;
            double nTotal = 0;
            for (int nDirection = -1; nDirection <= 1; nDirection += 2)
            {
                int nTransitions = 0;
                bool bPrevious = true;
                double nDistance;
                for (nDistance = 0; nDistance < oFrom.Module * 8; nDistance += 0.25)
                {
                    int nX = (int)Math.Floor(oFrom.X + nDistance * nDx * nDirection);
                    int nY = (int)Math.Floor(oFrom.Y + nDistance * nDy * nDirection);
                    if ((uint)nX >= nWidth || (uint)nY >= nHeight) return 0;
                    bool bCurrent = oDark[nY * nWidth + nX];
                    if (bCurrent == bPrevious) continue;
                    bPrevious = bCurrent;
                    if (++nTransitions == 3) break;
                }
                if (nTransitions != 3) return 0;
                nTotal += nDistance - 0.125;
            }
            return nTotal / 7;
        }

        private static bool[] Sample(bool[] oDark, int nWidth, int nHeight, Finder oCorner,
            Finder oRight, Finder oBottom, int nVersion)
        {
            // shortcut: Target flat images and screenshots; add perspective correction for angled camera photos.
            int nSize = nVersion * 4 + 17;
            double nDx = (oRight.X - oCorner.X) / (nSize - 7), nDy = (oRight.Y - oCorner.Y) / (nSize - 7);
            double nEx = (oBottom.X - oCorner.X) / (nSize - 7), nEy = (oBottom.Y - oCorner.Y) / (nSize - 7);
            int Pixel(int x, int y)
            {
                int nSampleX = (int)Math.Floor(oCorner.X + (x - 3) * nDx + (y - 3) * nEx);
                int nSampleY = (int)Math.Floor(oCorner.Y + (x - 3) * nDy + (y - 3) * nEy);
                return (uint)nSampleX < nWidth && (uint)nSampleY < nHeight ? nSampleY * nWidth + nSampleX : -1;
            }

            // Verify all three finder squares in symbol coordinates before attempting a full decode.
            foreach ((int nLeft, int nTop) in new[] { (0, 0), (nSize - 7, 0), (0, nSize - 7) })
            {
                int nErrors = 0;
                for (int nY = 0; nY < 7; nY++)
                for (int nX = 0; nX < 7; nX++)
                {
                    int nPixel = Pixel(nLeft + nX, nTop + nY);
                    if (nPixel < 0 || oDark[nPixel] != (Math.Max(Math.Abs(nX - 3), Math.Abs(nY - 3)) != 2))
                        nErrors++;
                }
                if (nErrors > 3) return null;
            }
            bool[] oModules = new bool[nSize * nSize];
            for (int nY = 0; nY < nSize; nY++)
            for (int nX = 0; nX < nSize; nX++)
            {
                int nPixel = Pixel(nX, nY);
                if (nPixel < 0)
                {
                    Array.Clear(oModules);
                    return null;
                }
                oModules[nY * nSize + nX] = oDark[nPixel];
            }
            return oModules;
        }

        private static string DecodeModules(bool[] oModules, int nVersion, bool bMirrored)
        {
            int nSize = nVersion * 4 + 17;
            bool Module(int x, int y) => oModules[bMirrored ? x * nSize + y : y * nSize + x];

            // Both copies of the BCH-protected format identify the mask and parity block layout.
            int nFirst = 0, nSecond = 0;
            for (int nBit = 0; nBit < 15; nBit++)
            {
                int nX = nBit < 8 ? 8 : nBit == 8 ? 7 : 14 - nBit;
                int nY = nBit < 6 ? nBit : nBit < 8 ? nBit + 1 : 8;
                if (Module(nX, nY)) nFirst |= 1 << nBit;
                if (Module(nBit < 8 ? nSize - 1 - nBit : 8,
                    nBit < 8 ? 8 : nSize - 15 + nBit)) nSecond |= 1 << nBit;
            }
            int nFormat = -1, nDistance = 4;
            for (int nValue = 0; nValue < 32; nValue++)
            {
                int nBch = nValue << 10;
                for (int nBit = 14; nBit >= 10; nBit--)
                    if ((nBch & 1 << nBit) != 0) nBch ^= 0x537 << (nBit - 10);
                int nEncoded = ((nValue << 10) | nBch) ^ 0x5412;
                int nErrors = Math.Min(BitOperations.PopCount((uint)(nEncoded ^ nFirst)),
                    BitOperations.PopCount((uint)(nEncoded ^ nSecond)));
                if (nErrors < nDistance) { nDistance = nErrors; nFormat = nValue; }
                else if (nErrors == nDistance) nFormat = -1;
            }
            if (nFormat < 0) return null;
            if (nVersion >= 7)
            {
                int nBch = nVersion << 12;
                for (int nBit = 17; nBit >= 12; nBit--)
                    if ((nBch & 1 << nBit) != 0) nBch ^= 0x1F25 << (nBit - 12);
                int nEncoded = (nVersion << 12) | nBch;
                nFirst = nSecond = 0;
                for (int nBit = 0; nBit < 18; nBit++)
                {
                    if (Module(nSize - 11 + nBit % 3, nBit / 3)) nFirst |= 1 << nBit;
                    if (Module(nBit / 3, nSize - 11 + nBit % 3)) nSecond |= 1 << nBit;
                }
                if (Math.Min(BitOperations.PopCount((uint)(nEncoded ^ nFirst)),
                    BitOperations.PopCount((uint)(nEncoded ^ nSecond))) > 3) return null;
            }

            // Mark structural modules so only the zigzag data region is unmasked and read.
            bool[] oReserved = new bool[oModules.Length];
            void Reserve(int x, int y, int width, int height)
            {
                for (int nY = y; nY < y + height; nY++)
                    Array.Fill(oReserved, true, nY * nSize + x, width);
            }
            Reserve(0, 0, 9, 9);
            Reserve(nSize - 8, 0, 8, 9);
            Reserve(0, nSize - 8, 9, 8);
            Reserve(6, 0, 1, nSize);
            Reserve(0, 6, nSize, 1);
            if (nVersion > 1)
            {
                int nCount = nVersion / 7 + 2;
                int nStep = nVersion == 32 ? 26 : (nVersion * 4 + nCount * 2 + 1) / (nCount * 2 - 2) * 2;
                int[] oCenters = new int[nCount];
                oCenters[0] = 6;
                for (int nIndex = nCount - 1; nIndex > 0; nIndex--)
                    oCenters[nIndex] = nSize - 7 - (nCount - 1 - nIndex) * nStep;
                for (int nY = 0; nY < nCount; nY++)
                for (int nX = 0; nX < nCount; nX++)
                {
                    if (nX == 0 && (nY == 0 || nY == nCount - 1) || nY == 0 && nX == nCount - 1) continue;
                    Reserve(oCenters[nX] - 2, oCenters[nY] - 2, 5, 5);
                }
            }
            if (nVersion >= 7)
            {
                Reserve(nSize - 11, 0, 3, 6);
                Reserve(0, nSize - 11, 6, 3);
            }
            byte[] oCodewords = new byte[oReserved.Count(b => !b) / 8];
            int nPosition = 0, nMask = nFormat & 7;
            bool bUp = true;
            try
            {
                for (int nRight = nSize - 1; nRight >= 1; nRight -= 2)
                {
                    if (nRight == 6) nRight--;
                    for (int nRow = 0; nRow < nSize; nRow++)
                    for (int nColumn = 0; nColumn < 2; nColumn++)
                    {
                        int nX = nRight - nColumn, nY = bUp ? nSize - 1 - nRow : nRow;
                        if (oReserved[nY * nSize + nX] || nPosition >= oCodewords.Length * 8) continue;
                        bool bMask = nMask switch
                        {
                            0 => (nX + nY) % 2 == 0,
                            1 => nY % 2 == 0,
                            2 => nX % 3 == 0,
                            3 => (nX + nY) % 3 == 0,
                            4 => (nX / 3 + nY / 2) % 2 == 0,
                            5 => nX * nY % 2 + nX * nY % 3 == 0,
                            6 => (nX * nY % 2 + nX * nY % 3) % 2 == 0,
                            _ => ((nX + nY) % 2 + nX * nY % 3) % 2 == 0
                        };
                        if (Module(nX, nY) ^ bMask) oCodewords[nPosition / 8] |= (byte)(1 << (7 - nPosition % 8));
                        nPosition++;
                    }
                    bUp = !bUp;
                }
                return ReadBlocks(oCodewords, nVersion, nFormat >> 3);
            }
            finally { CryptographicOperations.ZeroMemory(oCodewords); }
        }

        private static string ReadBlocks(byte[] oCodewords, int nVersion, int nLevel)
        {
            int nCount = BlockCounts[nLevel][nVersion - 1], nParity = ParityCounts[nLevel][nVersion - 1];
            int nShortLength = oCodewords.Length / nCount;
            int nShortCount = nCount - oCodewords.Length % nCount;
            byte[][] oBlocks = new byte[nCount][];
            byte[] oData = new byte[oCodewords.Length - nCount * nParity];
            try
            {
                for (int nBlock = 0; nBlock < nCount; nBlock++)
                    oBlocks[nBlock] = new byte[nShortLength + (nBlock < nShortCount ? 0 : 1)];
                int nOffset = 0;
                for (int nColumn = 0; nColumn <= nShortLength - nParity; nColumn++)
                for (int nBlock = 0; nBlock < nCount; nBlock++)
                    if (nColumn < oBlocks[nBlock].Length - nParity)
                        oBlocks[nBlock][nColumn] = oCodewords[nOffset++];
                for (int nColumn = 0; nColumn < nParity; nColumn++)
                for (int nBlock = 0; nBlock < nCount; nBlock++)
                    oBlocks[nBlock][oBlocks[nBlock].Length - nParity + nColumn] = oCodewords[nOffset++];
                nOffset = 0;
                foreach (byte[] oBlock in oBlocks)
                {
                    if (!CorrectErrors(oBlock, nParity)) return null;
                    int nDataLength = oBlock.Length - nParity;
                    oBlock.AsSpan(0, nDataLength).CopyTo(oData.AsSpan(nOffset));
                    nOffset += nDataLength;
                }
                return ReadPayload(oData, nVersion);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oData);
                foreach (byte[] oBlock in oBlocks)
                    if (oBlock != null) CryptographicOperations.ZeroMemory(oBlock);
            }
        }

        private static byte Multiply(byte nA, byte nB) =>
            nA == 0 || nB == 0 ? (byte)0 : oExponents[oLogarithms[nA] + oLogarithms[nB]];

        private static byte Evaluate(ReadOnlySpan<byte> oPolynomial, byte nX)
        {
            byte nValue = 0;
            foreach (byte nCoefficient in oPolynomial) nValue = (byte)(Multiply(nValue, nX) ^ nCoefficient);
            return nValue;
        }

        private static bool CorrectErrors(Span<byte> oBlock, int nParity)
        {
            Span<byte> oSyndromes = stackalloc byte[30];
            Span<byte> oLocator = stackalloc byte[31];
            Span<byte> oPrevious = stackalloc byte[31];
            Span<byte> oSaved = stackalloc byte[31];
            Span<byte> oMatrix = stackalloc byte[15 * 16];
            Span<int> oPositions = stackalloc int[15];
            try
            {
                oLocator.Clear();
                oPrevious.Clear();

                bool bClean = true;
                for (int nIndex = 0; nIndex < nParity; nIndex++)
                {
                    oSyndromes[nIndex] = Evaluate(oBlock, oExponents[nIndex]);
                    bClean &= oSyndromes[nIndex] == 0;
                }
                if (bClean) return true;

                // Berlekamp-Massey finds the error locator from the parity syndromes.
                oLocator[0] = oPrevious[0] = 1;
                int nDegree = 0, nShift = 1;
                byte nLastDiscrepancy = 1;
                for (int nIndex = 0; nIndex < nParity; nIndex++)
                {
                    byte nDiscrepancy = oSyndromes[nIndex];
                    for (int nTerm = 1; nTerm <= nDegree; nTerm++)
                        nDiscrepancy ^= Multiply(oLocator[nTerm], oSyndromes[nIndex - nTerm]);
                    if (nDiscrepancy == 0) { nShift++; continue; }
                    oLocator.CopyTo(oSaved);
                    byte nScale = Multiply(nDiscrepancy, oExponents[255 - oLogarithms[nLastDiscrepancy]]);
                    for (int nTerm = 0; nTerm + nShift <= nParity; nTerm++)
                        oLocator[nTerm + nShift] ^= Multiply(nScale, oPrevious[nTerm]);
                    if (nDegree * 2 <= nIndex)
                    {
                        nDegree = nIndex + 1 - nDegree;
                        oSaved.CopyTo(oPrevious);
                        nLastDiscrepancy = nDiscrepancy;
                        nShift = 1;
                    }
                    else nShift++;
                }
                if (nDegree == 0 || nDegree * 2 > nParity) return false;

                // Locate damaged bytes, then solve their magnitudes in the same finite field.
                int nFound = 0;
                for (int nPosition = 0; nPosition < oBlock.Length; nPosition++)
                {
                    byte nRoot = oExponents[255 - (oBlock.Length - 1 - nPosition)];
                    byte nValue = oLocator[nDegree];
                    for (int nTerm = nDegree - 1; nTerm >= 0; nTerm--)
                        nValue = (byte)(Multiply(nValue, nRoot) ^ oLocator[nTerm]);
                    if (nValue != 0) continue;
                    if (nFound == nDegree) return false;
                    oPositions[nFound++] = nPosition;
                }
                if (nFound != nDegree) return false;
                int nStride = nDegree + 1;
                for (int nRow = 0; nRow < nDegree; nRow++)
                {
                    for (int nColumn = 0; nColumn < nDegree; nColumn++)
                        oMatrix[nRow * nStride + nColumn] =
                            oExponents[(nRow * (oBlock.Length - 1 - oPositions[nColumn])) % 255];
                    oMatrix[nRow * nStride + nDegree] = oSyndromes[nRow];
                }
                for (int nColumn = 0; nColumn < nDegree; nColumn++)
                {
                    int nPivot = nColumn;
                    while (nPivot < nDegree && oMatrix[nPivot * nStride + nColumn] == 0) nPivot++;
                    if (nPivot == nDegree) return false;
                    for (int nEntry = 0; nEntry < nStride; nEntry++)
                        (oMatrix[nColumn * nStride + nEntry], oMatrix[nPivot * nStride + nEntry]) =
                            (oMatrix[nPivot * nStride + nEntry], oMatrix[nColumn * nStride + nEntry]);
                    byte nInverse = oExponents[255 - oLogarithms[oMatrix[nColumn * nStride + nColumn]]];
                    for (int nEntry = nColumn; nEntry < nStride; nEntry++)
                        oMatrix[nColumn * nStride + nEntry] = Multiply(oMatrix[nColumn * nStride + nEntry], nInverse);
                    for (int nRow = 0; nRow < nDegree; nRow++)
                    {
                        if (nRow == nColumn) continue;
                        byte nScale = oMatrix[nRow * nStride + nColumn];
                        for (int nEntry = nColumn; nEntry < nStride; nEntry++)
                            oMatrix[nRow * nStride + nEntry] ^= Multiply(nScale, oMatrix[nColumn * nStride + nEntry]);
                    }
                }
                for (int nIndex = 0; nIndex < nDegree; nIndex++)
                    oBlock[oPositions[nIndex]] ^= oMatrix[nIndex * nStride + nDegree];
                for (int nIndex = 0; nIndex < nParity; nIndex++)
                    if (Evaluate(oBlock, oExponents[nIndex]) != 0) return false;
                return true;
            }
            finally
            {
                oSyndromes.Clear();
                oLocator.Clear();
                oPrevious.Clear();
                oSaved.Clear();
                oMatrix.Clear();
            }
        }

        private static string ReadPayload(byte[] oData, int nVersion)
        {
            const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
            StringBuilder oText = new StringBuilder();
            int nPosition = 0;
            int Read(int nBits)
            {
                if (nBits > oData.Length * 8 - nPosition) throw new FormatException();
                int nValue = 0;
                for (int nBit = 0; nBit < nBits; nBit++, nPosition++)
                    nValue = nValue << 1 | (oData[nPosition / 8] >> (7 - nPosition % 8) & 1);
                return nValue;
            }
            try
            {
                int nEncoding = -1;
                while (oData.Length * 8 - nPosition >= 4)
                {
                    int nMode = Read(4);
                    if (nMode == 0) break;
                    if (nMode == 7)
                    {
                        int nFirst = Read(8);
                        if (nFirst >= 192) return null;
                        nEncoding = nFirst < 128 ? nFirst : (nFirst & 63) << 8 | Read(8);
                        if (nEncoding is not (1 or 3 or 26 or 27 or 170)) return null;
                        continue;
                    }
                    // Setup URIs use numeric, alphanumeric, or byte segments; split-symbol formats are unsupported.
                    if (nMode is not (1 or 2 or 4)) return null;
                    int nCountBits = nMode == 4 ? (nVersion <= 9 ? 8 : 16) :
                        (nMode == 1 ? 10 : 9) + (nVersion <= 9 ? 0 : nVersion <= 26 ? 2 : 4);
                    int nCount = Read(nCountBits);
                    if (nCount > 4096 - oText.Length) return null;
                    if (nMode == 4)
                    {
                        if (nCount > (oData.Length * 8 - nPosition) / 8) return null;
                        byte[] oBytes = new byte[nCount];
                        try
                        {
                            for (int nIndex = 0; nIndex < nCount; nIndex++) oBytes[nIndex] = (byte)Read(8);
                            if (nEncoding is 27 or 170 && oBytes.Any(b => b >= 128)) return null;
                            if (nEncoding is 1 or 3) oText.Append(Encoding.Latin1.GetString(oBytes));
                            else
                            {
                                try { oText.Append(Utf8.GetString(oBytes)); }
                                catch (DecoderFallbackException) when (nEncoding == -1)
                                {
                                    oText.Append(Encoding.Latin1.GetString(oBytes));
                                }
                            }
                        }
                        finally { CryptographicOperations.ZeroMemory(oBytes); }
                    }
                    else if (nMode == 2)
                    {
                        for (int nIndex = 0; nIndex < nCount; nIndex += 2)
                        {
                            int nValue = Read(nCount - nIndex >= 2 ? 11 : 6);
                            if (nValue >= (nCount - nIndex >= 2 ? 45 * 45 : 45)) return null;
                            if (nCount - nIndex >= 2) oText.Append(Alphabet[nValue / 45]);
                            oText.Append(Alphabet[nValue % 45]);
                        }
                    }
                    else
                    {
                        for (int nIndex = 0; nIndex < nCount; nIndex += 3)
                        {
                            int nDigits = Math.Min(3, nCount - nIndex);
                            int nValue = Read(nDigits == 3 ? 10 : nDigits == 2 ? 7 : 4);
                            int nDivisor = nDigits == 3 ? 100 : nDigits == 2 ? 10 : 1;
                            if (nValue >= nDivisor * 10) return null;
                            for (; nDivisor > 0; nDivisor /= 10)
                                oText.Append((char)('0' + nValue / nDivisor % 10));
                        }
                    }
                }
                return oText.ToString();
            }
            catch (Exception oError) when (oError is FormatException or DecoderFallbackException) { return null; }
        }
    }
}
