import asyncio
from api_context import Context


async def main():

	ctx = Context()
	#ctx.initialize(application)
	await ctx.initialize()



if __name__ == '__main__':
	asyncio.run(main())
	



