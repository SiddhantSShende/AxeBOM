# `hbom-nested`

A four-level hardware assembly, and what each part of it proves.

## What this fixture is for

| Property | Where it appears |
|---|---|
| **Four levels of nesting** | gateway → mainboard → DDR3L SDRAM → memory die |
| **Both supplier relationships, populated distinctly** | the gateway has a *product* supplier (Bharat Integrators); its components have *component* suppliers (Arrow, Mouser, Kaveri) |
| **Level returns to a shallower depth** | row 6 (`W25Q128JV`, level 2) follows row 5 (`MT41K-DIE`, level 3) |
| **A repeated supplier across sub-assemblies** | Arrow and Mouser each supply parts under different parents |
| **Every §10.4.1.4 element on at least one row** | firmware version, origin, criticality, and vulnerabilities (matched, not imported) |
| **Fields that are honestly absent** | warranty, licence terms and test result appear nowhere — no parts list has them |

## The two supplier relationships

This is the fixture's main job. CERT-In Table 11 lists "Supplier Information"
and "Supplier Location" **twice**, with different descriptions, and the
distinction is easy to collapse by accident:

- **Product supplier** — who sold you the finished gateway. Bharat Integrators
  Ltd, New Delhi. Set on the level-0 row only.
- **Component supplier** — who supplied a part to the *manufacturer* of the
  larger product. Arrow Electronics supplies the STM32 to Encore Systems; Encore
  did not buy it from Bharat.

A normalizer that put both in one column would produce a BOM saying Arrow sold
the customer a gateway, which is false and unfalsifiable from the output.

## Why the origins vary

Switzerland, USA, Taiwan and India in one assembly is not decoration — §10.2.1
makes an HBOM a supply-chain provenance document, and a fixture where everything
comes from one country cannot demonstrate that the origin field carries a real
signal.

## What is deliberately missing

`warranty`, `license`, `test_result` and — on most rows — `criticality` are
absent, because **no CAD or ERP export contains them**. They are judgements a
customer makes about their own hardware, collected by the manual entry form.
Their absence here is the honest state of a CSV import, and the coverage number
this fixture produces is supposed to reflect that rather than be flattered by a
fixture that quietly fills them in.
